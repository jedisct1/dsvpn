const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const dsvpn = b.addExecutable(.{
        .name = "dsvpn",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });
    dsvpn.root_module.link_libc = true;
    dsvpn.root_module.addIncludePath(b.path("include"));
    dsvpn.root_module.addCMacro("_GNU_SOURCE", "1");
    const source_files = &.{ "src/charm.c", "src/os.c", "src/vpn.c" };
    dsvpn.root_module.addCSourceFiles(.{ .files = source_files });
    b.installArtifact(dsvpn);
    const run_cmd = b.addRunArtifact(dsvpn);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
