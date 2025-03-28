#pragma once

// estimate: 1000 concurrent processes (including children) * 3 namespaces per pid
enum { k_max_concurrent_pids = 3001 };
