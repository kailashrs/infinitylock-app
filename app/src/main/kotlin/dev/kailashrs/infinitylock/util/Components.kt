package dev.kailashrs.infinitylock.util
import android.content.ComponentName
import android.content.Context
fun componentName(context: Context, type: Class<*>) = ComponentName(context, type)
