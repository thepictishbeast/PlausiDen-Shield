//! System dashboard API — CPU, memory, disk, network metrics via sysinfo.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use sysinfo::{Disks, Networks, System};

use crate::auth::{rbac::Permission, require_permission, AuthUser};
use crate::AppState;

#[derive(Serialize)]
pub struct SystemOverview {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub uptime_seconds: u64,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub network: Vec<NetworkInfo>,
    pub load_average: LoadAverage,
}

#[derive(Serialize)]
pub struct CpuInfo {
    pub core_count: usize,
    pub usage_percent: f32,
    pub per_core: Vec<f32>,
}

#[derive(Serialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Serialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Serialize)]
pub struct NetworkInfo {
    pub interface: String,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

#[derive(Serialize)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

/// GET /api/system — full system overview.
pub async fn get_system_overview(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<SystemOverview>, StatusCode> {
    require_permission(&user, Permission::ViewDashboard)?;

    let mut sys = state.system.lock().await;
    sys.refresh_all();

    let cpu_usage: Vec<f32> = sys.cpus().iter().map(|c| c.cpu_usage()).collect();
    let avg_cpu = if cpu_usage.is_empty() {
        0.0
    } else {
        cpu_usage.iter().sum::<f32>() / cpu_usage.len() as f32
    };

    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let mem_percent = if total_mem > 0 {
        (used_mem as f64 / total_mem as f64) * 100.0
    } else {
        0.0
    };

    let disks = Disks::new_with_refreshed_list();
    let disk_info: Vec<DiskInfo> = disks
        .iter()
        .map(|d| {
            let total = d.total_space();
            let avail = d.available_space();
            let usage = if total > 0 {
                ((total - avail) as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            DiskInfo {
                name: d.name().to_string_lossy().to_string(),
                mount_point: d.mount_point().to_string_lossy().to_string(),
                fs_type: d.file_system().to_string_lossy().to_string(),
                total_bytes: total,
                available_bytes: avail,
                usage_percent: usage,
            }
        })
        .collect();

    let networks = Networks::new_with_refreshed_list();
    let net_info: Vec<NetworkInfo> = networks
        .iter()
        .map(|(name, data)| NetworkInfo {
            interface: name.clone(),
            received_bytes: data.total_received(),
            transmitted_bytes: data.total_transmitted(),
        })
        .collect();

    let la = System::load_average();

    let overview = SystemOverview {
        hostname: System::host_name().unwrap_or_default(),
        os: System::long_os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        uptime_seconds: System::uptime(),
        cpu: CpuInfo {
            core_count: sys.cpus().len(),
            usage_percent: avg_cpu,
            per_core: cpu_usage,
        },
        memory: MemoryInfo {
            total_bytes: total_mem,
            used_bytes: used_mem,
            available_bytes: sys.available_memory(),
            swap_total_bytes: sys.total_swap(),
            swap_used_bytes: sys.used_swap(),
            usage_percent: mem_percent,
        },
        disks: disk_info,
        network: net_info,
        load_average: LoadAverage {
            one: la.one,
            five: la.five,
            fifteen: la.fifteen,
        },
    };

    Ok(Json(overview))
}
