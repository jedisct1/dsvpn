const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.build.Builder) !void {
    var target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const dsvpn = b.addExecutable(.{
        .name = "dsvpn",
        .target = target,
        .optimize = optimize,
    });
    dsvpn.linkLibC();
    dsvpn.strip = true;
    dsvpn.addIncludePath(.{ .path = "include" });
    dsvpn.defineCMacro("_GNU_SOURCE", "1");
    const source_files = &.{ "src/charm.c", "src/os.c", "src/vpn.c" };
    if (@hasDecl(std.Build.Step.Compile, "AddCSourceFilesOptions")) {
        dsvpn.addCSourceFiles(.{ .files = source_files });
    } else {
        dsvpn.addCSourceFiles(source_files, &.{});
    }
    b.installArtifact(dsvpn);
    const run_cmd = b.addRunArtifact(dsvpn);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
