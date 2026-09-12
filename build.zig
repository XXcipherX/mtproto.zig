const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const tsan = b.option(
        bool,
        "tsan",
        "Instrument test and soak artifacts with ThreadSanitizer (default: false)",
    ) orelse false;

    // The proxy parses untrusted network input (FakeTLS, obfuscation,
    // MiddleProxy, WEB, SOCKS5 and TOML). Keep runtime bounds, overflow and null
    // checks enabled in production: a parser defect must fail closed instead of
    // becoming unchecked undefined behaviour. Bench and soak retain the requested
    // mode so ReleaseFast measurements remain meaningful. Operators can explicitly
    // restore the requested mode with -Ddataplane_safety=false.
    const dataplane_safety = b.option(
        bool,
        "dataplane_safety",
        "Build the internet-facing proxy with runtime safety on (ReleaseSafe) even in release builds (default: true)",
    ) orelse true;
    const dataplane_optimize: std.builtin.OptimizeMode =
        if (dataplane_safety and optimize == .ReleaseFast) .ReleaseSafe else optimize;

    const production_options = b.addOptions();
    production_options.addOption(bool, "e2e_test_hooks", false);
    const production_options_mod = production_options.createModule();

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = dataplane_optimize,
        .imports = &.{.{ .name = "build_options", .module = production_options_mod }},
    });

    const exe = b.addExecutable(.{
        .name = "mtproto-proxy",
        .root_module = exe_mod,
    });

    // Build an ELF position-independent executable so Linux can randomize its
    // load address with ASLR. Zig already links immediate binding + RELRO by
    // default; ReleaseSafe supplies the data-plane bounds and overflow checks.
    exe.pie = true;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the proxy");
    run_step.dependOn(&run_cmd.step);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = tsan,
    });

    const bench_exe = b.addExecutable(.{
        .name = "mtproto-bench",
        .root_module = bench_mod,
    });

    const install_bench = b.addInstallArtifact(bench_exe, .{});
    const install_bench_step = b.step("install-bench", "Install the benchmark binary");
    install_bench_step.dependOn(&install_bench.step);

    const run_bench_cmd = b.addRunArtifact(bench_exe);
    if (b.args) |args| {
        run_bench_cmd.addArgs(args);
    }

    const bench_step = b.step("bench", "Run encapsulation microbenchmarks");
    bench_step.dependOn(&run_bench_cmd.step);

    const run_soak_cmd = b.addRunArtifact(bench_exe);
    run_soak_cmd.addArg("soak");
    if (b.args) |args| {
        run_soak_cmd.addArgs(args);
    }

    const soak_step = b.step("soak", "Run multithreaded soak stress test");
    soak_step.dependOn(&run_soak_cmd.step);

    // The WEB bridge is JavaScript executed inside Telegram Desktop's hidden WebView,
    // so Zig unit tests cannot exercise its client-facing contract. CI drives the
    // production renderer and a Node harness. Missing tools must fail this target.
    const web_bridge_cmd = b.addSystemCommand(&.{"python3"});
    web_bridge_cmd.addFileArg(b.path("test/web-bridge/run.py"));
    web_bridge_cmd.setEnvironmentVariable("ZIG", b.graph.zig_exe);
    const web_bridge_step = b.step("web-bridge", "Run WEB proxy bridge-page contract tests");
    web_bridge_step.dependOn(&web_bridge_cmd.step);

    // Process-level E2E uses the production root module with one compile-time-only
    // loopback DC override. The installed daemon is built from production_options,
    // so this test hook is absent from shipping binaries.
    const e2e_options = b.addOptions();
    e2e_options.addOption(bool, "e2e_test_hooks", true);
    const e2e_proxy_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = dataplane_optimize,
        .imports = &.{.{ .name = "build_options", .module = e2e_options.createModule() }},
    });
    const e2e_proxy = b.addExecutable(.{
        .name = "mtproto-proxy-e2e",
        .root_module = e2e_proxy_mod,
    });
    e2e_proxy.pie = true;

    const obf_gen = b.addExecutable(.{
        .name = "e2e-obf-handshake-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/e2e_obf_handshake_gen.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const e2e_cmd = b.addSystemCommand(&.{"python3"});
    e2e_cmd.addFileArg(b.path("test/process_e2e.py"));
    e2e_cmd.addArg("--proxy-bin");
    e2e_cmd.addFileArg(e2e_proxy.getEmittedBin());
    e2e_cmd.addArg("--obf-gen");
    e2e_cmd.addFileArg(obf_gen.getEmittedBin());
    if (b.args) |args| e2e_cmd.addArgs(args);

    const e2e_step = b.step("e2e", "Run real-process relay E2E tests");
    e2e_step.dependOn(&e2e_cmd.step);

    // Tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = tsan,
        .imports = &.{.{ .name = "build_options", .module = production_options_mod }},
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Keep coverage-guided security fuzzing isolated from the benchmark test
    // binary. Invoke with a bounded iteration count in CI, for example:
    // `zig build -Doptimize=ReleaseSafe fuzz --fuzz=100K`.
    const fuzz_step = b.step("fuzz", "Run wire-facing security fuzz harnesses");
    fuzz_step.dependOn(&run_unit_tests.step);

    const bench_test_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = tsan,
    });

    const bench_tests = b.addTest(.{
        .root_module = bench_test_mod,
    });

    const run_bench_tests = b.addRunArtifact(bench_tests);
    test_step.dependOn(&run_bench_tests.step);
}
