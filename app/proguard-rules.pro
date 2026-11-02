# Shizuku user service must survive R8
-keep class dev.kailashrs.infinitylock.shell.ShellService {
    public <init>();
    public <init>(android.content.Context);
    *;
}
-keep class dev.kailashrs.infinitylock.shell.** { *; }
