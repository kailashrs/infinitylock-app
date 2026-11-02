package dev.kailashrs.infinitylock.shell

import android.os.Parcel
import android.os.Parcelable

/** Merged-command result crossing the Shizuku binder. */
class ExecResult(val exitCode: Int, val output: String) : Parcelable {

    constructor(parcel: Parcel) : this(parcel.readInt(), parcel.readString() ?: "")

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(exitCode)
        dest.writeString(output)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<ExecResult> {
        override fun createFromParcel(parcel: Parcel): ExecResult = ExecResult(parcel)
        override fun newArray(size: Int): Array<ExecResult?> = arrayOfNulls(size)
    }

    override fun toString(): String = "ExecResult(exit=$exitCode, ${output.length} chars)"
}
