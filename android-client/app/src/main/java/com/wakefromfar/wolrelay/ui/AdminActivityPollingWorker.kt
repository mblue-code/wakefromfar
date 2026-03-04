package com.wakefromfar.wolrelay.ui

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.wakefromfar.wolrelay.data.ApiClient
import com.wakefromfar.wolrelay.data.ApiException
import com.wakefromfar.wolrelay.data.SecurePrefs
import java.util.concurrent.TimeUnit
import org.json.JSONObject

class AdminActivityPollingWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    private val prefs = SecurePrefs(appContext)
    private val api = ApiClient()
    private val notifications = AdminNotificationDispatcher(appContext)

    override suspend fun doWork(): Result {
        val token = prefs.getToken()
        val backendUrl = prefs.getBackendUrl().trim()
        if (token.isNullOrBlank() || backendUrl.isBlank()) {
            AdminActivityBackgroundScheduler.cancel(applicationContext)
            return Result.success()
        }
        if (!isAdminToken(token)) {
            AdminActivityBackgroundScheduler.cancel(applicationContext)
            return Result.success()
        }

        return try {
            val events = api.listAdminEvents(
                baseUrl = backendUrl,
                token = token,
                limit = ACTIVITY_PAGE_SIZE,
                typeFilter = "wake,poke",
            )
            val previousEventId = prefs.getLastSeenAdminActivityEventId()
            val latestEventId = events.maxOfOrNull { it.id }
            val newShutdownRequests = if (previousEventId > 0) {
                events.filter { it.id > previousEventId && it.event_type == SHUTDOWN_REQUEST_EVENT_TYPE }
            } else {
                emptyList()
            }

            notifications.notifyShutdownRequests(newShutdownRequests)
            if (latestEventId != null && latestEventId > previousEventId) {
                prefs.setLastSeenAdminActivityEventId(latestEventId)
            }
            Log.d(TAG, "Background poll success events=${events.size} new_shutdown=${newShutdownRequests.size}")

            AdminActivityBackgroundScheduler.scheduleNextShortPoll(applicationContext)
            Result.success()
        } catch (ex: Exception) {
            Log.w(TAG, "Background poll failed", ex)
            if (isUnauthorized(ex)) {
                AdminActivityBackgroundScheduler.cancel(applicationContext)
                return Result.success()
            }
            Result.retry()
        }
    }

    private fun isAdminToken(token: String): Boolean {
        val parts = token.split(".")
        if (parts.size < 2) {
            return false
        }
        return try {
            val payloadBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            val role = JSONObject(String(payloadBytes, Charsets.UTF_8)).optString("role")
            role == "admin"
        } catch (_: Exception) {
            false
        }
    }

    private fun isUnauthorized(ex: Exception): Boolean {
        if (ex !is ApiException) {
            return false
        }
        return ex.message?.contains("(401)") == true || ex.message?.contains("(403)") == true
    }

    private companion object {
        const val TAG = "AdminActivityWorker"
        const val SHUTDOWN_REQUEST_EVENT_TYPE = "shutdown_poke_requested"
        const val ACTIVITY_PAGE_SIZE = 30
    }
}

object AdminActivityBackgroundScheduler {
    private val networkConstraint: Constraints = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .build()

    fun ensureScheduled(context: Context) {
        val appContext = context.applicationContext
        val prefs = SecurePrefs(appContext)
        val token = prefs.getToken()
        if (token.isNullOrBlank() || !isAdminToken(token)) {
            cancel(appContext)
            return
        }

        val periodicRequest = PeriodicWorkRequestBuilder<AdminActivityPollingWorker>(
            15,
            TimeUnit.MINUTES,
        )
            .setConstraints(networkConstraint)
            .addTag(TAG)
            .build()

        WorkManager.getInstance(appContext).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            periodicRequest,
        )
        scheduleNextShortPoll(appContext, initialDelaySeconds = 20L)
    }

    fun scheduleNextShortPoll(context: Context, initialDelaySeconds: Long = 60L) {
        val appContext = context.applicationContext
        val shortPollRequest = OneTimeWorkRequestBuilder<AdminActivityPollingWorker>()
            .setInitialDelay(initialDelaySeconds, TimeUnit.SECONDS)
            .setConstraints(networkConstraint)
            .addTag(TAG)
            .build()

        WorkManager.getInstance(appContext).enqueueUniqueWork(
            SHORT_POLL_WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            shortPollRequest,
        )
    }

    fun cancel(context: Context) {
        val appContext = context.applicationContext
        val wm = WorkManager.getInstance(appContext)
        wm.cancelUniqueWork(PERIODIC_WORK_NAME)
        wm.cancelUniqueWork(SHORT_POLL_WORK_NAME)
    }

    private const val PERIODIC_WORK_NAME = "admin-activity-poll-periodic"
    private const val SHORT_POLL_WORK_NAME = "admin-activity-poll-short"
    private const val TAG = "admin-activity-poll"

    private fun isAdminToken(token: String): Boolean {
        val parts = token.split(".")
        if (parts.size < 2) {
            return false
        }
        return try {
            val payloadBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            val role = JSONObject(String(payloadBytes, Charsets.UTF_8)).optString("role")
            role == "admin"
        } catch (_: Exception) {
            false
        }
    }
}
