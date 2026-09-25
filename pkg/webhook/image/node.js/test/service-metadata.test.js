"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const {
  detectServiceMetadata,
  entryPointFromProcess,
  maxPackageJsonBytes,
  parsePackageName,
  readPackageJson,
} = require("../service-metadata");

// Creates an isolated application tree for one metadata test.
function createProject(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "beyla-node-metadata-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  return {
    root,
    // Writes a fixture file and returns its absolute path.
    write(filename, contents = "") {
      const target = path.join(root, filename);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, contents);
      return target;
    },
  };
}

test("scoped package supplies name, namespace, and version", t => {
  const project = createProject(t);
  project.write("app/dist/main.js");
  project.write("app/package.json", '{"name":"@acme/orders","version":"1.2.3"}');

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "dist/main.js",
    env: {},
  });

  assert.deepEqual(
    { name: metadata.name, namespace: metadata.namespace, version: metadata.version },
    { name: "orders", namespace: "acme", version: "1.2.3" },
  );
  assert.equal(metadata.nameSource, "package.json");
});

test("nearest package is a boundary when its name is invalid", t => {
  const project = createProject(t);
  project.write("app/package.json", '{"name":"outer","version":"1"}');
  project.write("app/packages/api/package.json", '{"name":"bad/name/again","version":"2"}');
  project.write("app/packages/api/dist/main.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "packages/api/dist/main.js",
    env: {},
  });

  assert.equal(metadata.name, "main");
  assert.equal(metadata.version, "2");
  assert.equal(metadata.nameSource, "Node.js entrypoint");
});

test("malformed nearest package does not leak the parent identity", t => {
  const project = createProject(t);
  project.write("app/package.json", '{"name":"outer"}');
  project.write("app/packages/api/package.json", "{");
  project.write("app/packages/api/main.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "packages/api/main.js",
    env: {},
  });

  assert.equal(metadata.name, "main");
  assert.match(metadata.warning, /could not read package metadata/);
});

test("npm package path takes precedence outside the working directory", t => {
  const project = createProject(t);
  const workspacePackage = project.write("workspace/package.json", '{"name":"workspace"}');
  project.write("app/package.json", '{"name":"application"}');
  project.write("app/main.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "main.js",
    env: { npm_package_json: workspacePackage },
  });

  assert.equal(metadata.name, "workspace");
});

test("npm package path inside node_modules is ignored", t => {
  const project = createProject(t);
  project.write("app/package.json", '{"name":"application"}');
  project.write("app/main.js");
  const dependencyPackage = project.write(
    "app/node_modules/tool/package.json",
    '{"name":"tool"}',
  );

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "main.js",
    env: { npm_package_json: dependencyPackage },
  });

  assert.equal(metadata.name, "application");
});

test("node_modules entrypoint restarts package lookup from cwd", t => {
  const project = createProject(t);
  project.write("app/package.json", '{"name":"application"}');
  project.write("app/node_modules/tool/package.json", '{"name":"tool"}');
  project.write("app/node_modules/tool/cli.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "node_modules/tool/cli.js",
    env: {},
  });

  assert.equal(metadata.name, "application");
});

test("launch without an entrypoint uses the cwd package", t => {
  const project = createProject(t);
  project.write("app/package.json", '{"name":"eval-service"}');

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "",
    env: {},
  });

  assert.equal(metadata.name, "eval-service");
});

test("process entrypoint ignores arguments to code launch modes", () => {
  assert.equal(entryPointFromProcess(["node", "worker.js"], ["-e", "run()"]), "");
  assert.equal(entryPointFromProcess(["node", "worker.js"], ["-pe", "run()"]), "");
  assert.equal(entryPointFromProcess(["node", "worker.js"], ["--run", "build"]), "");
});

test("process entrypoint accepts scripts and file entry URLs", () => {
  assert.equal(entryPointFromProcess(["node", "/app/main.js"], ["--inspect"]), "/app/main.js");
  assert.equal(
    entryPointFromProcess(["node"], ["--entry-url=file:///app/main.js"]),
    "/app/main.js",
  );
});

test("explicit entrypoint extensions are accepted", async t => {
  for (const extension of [".js", ".mjs", ".cjs", ".ts", ".jsx"]) {
    await t.test(extension, child => {
      const project = createProject(child);
      project.write(`app/client${extension}`);
      const metadata = detectServiceMetadata({
        cwd: path.join(project.root, "app"),
        entryPoint: `client${extension}`,
        env: {},
      });
      assert.equal(metadata.name, "client");
    });
  }
});

test("extensionless entrypoint resolves only Node runtime extensions", async t => {
  for (const extension of [".js", ".json", ".node"]) {
    await t.test(extension, child => {
      const project = createProject(child);
      project.write(`app/client${extension}`);
      const metadata = detectServiceMetadata({
        cwd: path.join(project.root, "app"),
        entryPoint: "client",
        env: {},
      });
      assert.equal(metadata.name, "client");
    });
  }
});

test("extensionless entrypoint does not infer source extensions", async t => {
  for (const extension of [".mjs", ".cjs", ".ts"]) {
    await t.test(extension, child => {
      const project = createProject(child);
      project.write(`app/client${extension}`);
      const metadata = detectServiceMetadata({
        cwd: path.join(project.root, "app"),
        entryPoint: "client",
        env: {},
      });
      assert.equal(metadata.name, "");
    });
  }
});

test("directory entrypoint resolves package main and index fallbacks", async t => {
  await t.test("package main", child => {
    const project = createProject(child);
    project.write("app/orders/package.json", '{"main":"lib/server"}');
    project.write("app/orders/lib/server.js");
    const metadata = detectServiceMetadata({
      cwd: path.join(project.root, "app"),
      entryPoint: "orders",
      env: {},
    });
    assert.equal(metadata.name, "orders");
  });

  await t.test("directory index", child => {
    const project = createProject(child);
    project.write("app/orders/package.json", "{}");
    project.write("app/orders/index.js");
    const metadata = detectServiceMetadata({
      cwd: path.join(project.root, "app"),
      entryPoint: "orders",
      env: {},
    });
    assert.equal(metadata.name, "orders");
  });

  await t.test("package main directory", child => {
    const project = createProject(child);
    project.write("app/orders/package.json", '{"main":"lib/server"}');
    project.write("app/orders/lib/server/index.js");
    const metadata = detectServiceMetadata({
      cwd: path.join(project.root, "app"),
      entryPoint: "orders",
      env: {},
    });
    assert.equal(metadata.name, "orders");
  });

  await t.test("missing package main falls back to directory index", child => {
    const project = createProject(child);
    project.write("app/orders/package.json", '{"main":"missing"}');
    project.write("app/orders/index.js");
    const metadata = detectServiceMetadata({
      cwd: path.join(project.root, "app"),
      entryPoint: "orders",
      env: {},
    });
    assert.equal(metadata.name, "orders");
  });
});

test("malformed directory package blocks its index fallback", t => {
  const project = createProject(t);
  project.write("app/orders/package.json", "{");
  project.write("app/orders/index.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "orders",
    env: {},
  });

  assert.equal(metadata.name, "");
});

test("package lookup follows a resolved file before a sibling directory", t => {
  const project = createProject(t);
  project.write("app/package.json", '{"name":"application"}');
  project.write("app/orders.js");
  project.write("app/orders/package.json", '{"name":"wrong"}');

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "orders",
    env: {},
  });

  assert.equal(metadata.name, "application");
});

test("missing entrypoint is not used as a fallback", t => {
  const project = createProject(t);
  fs.mkdirSync(path.join(project.root, "app"), { recursive: true });

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "missing.js",
    env: {},
  });

  assert.equal(metadata.name, "");
});

test("unresolvable directory entrypoint is not used as a fallback", t => {
  const project = createProject(t);
  project.write("app/orders/package.json", '{"main":"missing"}');

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "orders",
    env: {},
  });

  assert.equal(metadata.name, "");
});

test("extensionless regular file supplies its exact name", t => {
  const project = createProject(t);
  project.write("app/client");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "client",
    env: {},
  });

  assert.equal(metadata.name, "client");
});

test("entrypoint path must resolve to a regular file", t => {
  const project = createProject(t);
  fs.mkdirSync(path.join(project.root, "app/client.js"), { recursive: true });

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "client.js",
    env: {},
  });

  assert.equal(metadata.name, "");
});

test("node_modules entrypoint is not used without application metadata", t => {
  const project = createProject(t);
  project.write("app/node_modules/tool/cli.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: "node_modules/tool/cli.js",
    env: {},
  });

  assert.equal(metadata.name, "");
});

test("file URL entrypoint supplies the fallback name", t => {
  const project = createProject(t);
  const entryPoint = project.write("app/main.js");

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "app"),
    entryPoint: pathToFileURL(entryPoint).href,
    env: {},
  });

  assert.equal(metadata.name, "main");
});

test("working directory basename is not a service-name fallback", t => {
  const project = createProject(t);
  fs.mkdirSync(path.join(project.root, "orders"), { recursive: true });

  const metadata = detectServiceMetadata({
    cwd: path.join(project.root, "orders"),
    entryPoint: "",
    env: {},
  });

  assert.equal(metadata.name, "");
});

test("package names follow OBI validation", () => {
  assert.deepEqual(parsePackageName(" orders "), { name: "orders", namespace: "" });
  assert.deepEqual(parsePackageName("@acme/orders"), { name: "orders", namespace: "acme" });
  const invalidNames = [
    "",
    "@acme",
    "@/orders",
    "@acme/",
    "@acme/orders/worker",
    "acme/orders",
    "orders\nworker",
  ];
  for (const value of invalidNames) {
    assert.equal(parsePackageName(value), null);
  }
});

test("oversized and symlinked package files remain boundaries", async t => {
  await t.test("oversized", child => {
    const project = createProject(child);
    const filename = project.write("package.json", Buffer.alloc(maxPackageJsonBytes + 1));
    const result = readPackageJson(filename);
    assert.equal(result.found, true);
    assert.equal(result.metadata.valid, false);
  });

  await t.test("symlink", child => {
    const project = createProject(child);
    const target = project.write("target.json", '{"name":"outside"}');
    const filename = path.join(project.root, "package.json");
    fs.symlinkSync(target, filename);
    const result = readPackageJson(filename);
    assert.equal(result.found, true);
    assert.equal(result.metadata.valid, false);
  });
});

test("package fields are decoded independently", t => {
  const project = createProject(t);
  const filename = project.write("package.json", '{"name":"orders","version":1}');

  const result = readPackageJson(filename);

  assert.equal(result.metadata.name, "orders");
  assert.equal(result.metadata.version, "");
});
