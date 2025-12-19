const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const root_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = true,
    });
    root_module.addIncludePath(b.path("include"));
    root_module.addCMacro("_GNU_SOURCE", "1");
    const source_files = &.{ "src/charm.c", "src/os.c", "src/vpn.c" };
    root_module.addCSourceFiles(.{ .files = source_files });

    const dsvpn = b.addExecutable(.{
        .name = "dsvpn",
        .root_module = root_module,
    });
    b.installArtifact(dsvpn);

    const run_cmd = b.addRunArtifact(dsvpn);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
