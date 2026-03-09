package com.wakefromfar.wolrelay.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import com.wakefromfar.wolrelay.MainActivity
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.ApiClient
import com.wakefromfar.wolrelay.data.ApiException
import com.wakefromfar.wolrelay.data.SecurePrefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

class AdminAlertForegroundService : Service() {
    private val prefs by lazy { SecurePrefs(applicationContext) }
    private val api = ApiClient()
    private val notifications by lazy { AdminNotificationDispatcher(applicationContext) }
    private var serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pollingJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundWithStatusNotification()
        ensurePollingLoop()
        return START_STICKY
    }

    override fun onDestroy() {
        stopServiceWork()
        super.onDestroy()
    }

    private fun ensurePollingLoop() {
        if (!serviceScope.isActive) {
            serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        }
        if (pollingJob?.isActive == true) {
            return
        }
        pollingJob = serviceScope.launch {
            while (isActive) {
                try {
                    val shouldContinue = pollOnce()
                    if (!shouldContinue) {
                        stopSelf()
                        break
                    }
                } catch (ex: Exception) {
                    Log.w(TAG, "Foreground admin poll failed", ex)
                    if (isUnauthorized(ex)) {
                        stopSelf()
                        break
                    }
                }
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private suspend fun pollOnce(): Boolean {
        val token = prefs.getToken()
        val backendUrl = prefs.getBackendUrl().trim()
        if (token.isNullOrBlank() || backendUrl.isBlank() || !isAdminToken(token)) {
            return false
        }

        val events = api.listAdminEvents(
            baseUrl = backendUrl,
            token = token,
            limit = ACTIVITY_PAGE_SIZE,
            typeFilter = "poke",
            installationId = prefs.getInstallationId(),
        )
        val latestEventId = events.maxOfOrNull { it.id }
        val previousNotifiedId = prefs.getLastNotifiedShutdownEventId()

        if (latestEventId != null && previousNotifiedId <= 0) {
            // Prime the watermark so first run doesn't notify historical requests.
            prefs.setLastNotifiedShutdownEventId(latestEventId)
            return true
        }

        val newShutdownRequests = events.filter {
            it.id > previousNotifiedId && it.event_type == SHUTDOWN_REQUEST_EVENT_TYPE
        }
        notifications.notifyShutdownRequests(newShutdownRequests)

        if (latestEventId != null && latestEventId > previousNotifiedId) {
            prefs.setLastNotifiedShutdownEventId(latestEventId)
        }
        return true
    }

    private fun startForegroundWithStatusNotification() {
        ensureStatusChannel()
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(this, STATUS_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.notification_admin_monitoring_title))
            .setContentText(getString(R.string.notification_admin_monitoring_text))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()

        startForeground(STATUS_NOTIFICATION_ID, notification)
    }

    private fun ensureStatusChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(STATUS_CHANNEL_ID) != null) {
            return
        }
        val channel = NotificationChannel(
            STATUS_CHANNEL_ID,
            getString(R.string.notification_channel_admin_monitoring_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_admin_monitoring_description)
        }
        manager.createNotificationChannel(channel)
    }

    private fun stopServiceWork() {
        pollingJob?.cancel()
        pollingJob = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        serviceScope.cancel()
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

    companion object {
        private const val TAG = "AdminAlertService"
        private const val STATUS_CHANNEL_ID = "admin_monitoring_status"
        private const val STATUS_NOTIFICATION_ID = 1001
        private const val SHUTDOWN_REQUEST_EVENT_TYPE = "shutdown_poke_requested"
        private const val ACTIVITY_PAGE_SIZE = 30
        private const val POLL_INTERVAL_MS = 10 * 60 * 1000L
        private const val ACTION_START = "com.wakefromfar.wolrelay.action.ADMIN_ALERT_START"

        fun start(context: Context) {
            val appContext = context.applicationContext
            val intent = Intent(appContext, AdminAlertForegroundService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                appContext.startForegroundService(intent)
            } else {
                appContext.startService(intent)
            }
        }

        fun stop(context: Context) {
            val appContext = context.applicationContext
            val intent = Intent(appContext, AdminAlertForegroundService::class.java)
            appContext.stopService(intent)
        }
    }
}
