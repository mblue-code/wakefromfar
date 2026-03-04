package com.wakefromfar.wolrelay.ui

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.wakefromfar.wolrelay.MainActivity
import com.wakefromfar.wolrelay.R
import com.wakefromfar.wolrelay.data.ActivityEventDto
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

class AdminNotificationDispatcher(private val context: Context) {
    fun notifyShutdownRequests(events: List<ActivityEventDto>) {
        if (events.isEmpty()) {
            return
        }
        ensureChannel()
        if (!canPostNotifications()) {
            return
        }

        events
            .sortedBy { it.id }
            .forEach { event ->
                val note = event.shutdownRequestMessage()
                val summary = event.summary.trim()
                val contentText = if (note.isNullOrBlank()) {
                    summary
                } else {
                    context.getString(R.string.label_shutdown_note_inline, note)
                }
                val bigText = if (note.isNullOrBlank()) {
                    summary
                } else {
                    "$summary\n${context.getString(R.string.label_shutdown_note_inline, note)}"
                }

                val openAppIntent = Intent(context, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
                val pendingIntent = PendingIntent.getActivity(
                    context,
                    event.id,
                    openAppIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

                val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_launcher_foreground)
                    .setContentTitle(context.getString(R.string.notification_shutdown_request_title))
                    .setContentText(contentText)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                    .setAutoCancel(true)
                    .setContentIntent(pendingIntent)
                    .build()

                NotificationManagerCompat.from(context).notify(event.id, notification)
            }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val existing = manager.getNotificationChannel(CHANNEL_ID)
        if (existing != null) {
            return
        }
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notification_channel_shutdown_requests_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.notification_channel_shutdown_requests_description)
        }
        manager.createNotificationChannel(channel)
    }

    private fun canPostNotifications(): Boolean {
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) {
            return false
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return true
        }
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun ActivityEventDto.shutdownRequestMessage(): String? {
        if (event_type != SHUTDOWN_REQUEST_EVENT_TYPE) {
            return null
        }
        val value = metadata?.get("message")?.jsonPrimitive?.contentOrNull
        return value?.trim()?.ifBlank { null }
    }

    private companion object {
        const val CHANNEL_ID = "admin_shutdown_requests"
        const val SHUTDOWN_REQUEST_EVENT_TYPE = "shutdown_poke_requested"
    }
}
