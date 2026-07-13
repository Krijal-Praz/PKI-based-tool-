
// ===== HR USERS (EndpointTrust Verified Devices) =====

async function renderHRUsers(c) {
  c.innerHTML = `
    <div class="section-header">
      <div>
        <div class="section-title">HR Users from Verified Devices</div>
        <div style="font-size:12px;color:var(--text-tertiary);margin-top:4px">
          This section is empty until a laptop passes EndpointTrust PKI verification and enters the protected HR system.
        </div>
      </div>
      <button class="btn" onclick="renderHRUsers(document.getElementById('main-content'))"><i class="ti ti-refresh"></i> Refresh</button>
    </div>
    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr)">
      <div class="stat-card">
        <div class="stat-label">Verified HR Users</div>
        <div class="stat-value" id="hr-users-count">0</div>
        <div class="stat-delta delta-up"><i class="ti ti-shield-check"></i> EndpointTrust controlled</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Access Source</div>
        <div class="stat-value" style="font-size:20px">Nginx</div>
        <div class="stat-delta delta-neutral">Reverse proxy gateway</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Protection Status</div>
        <div class="stat-value" style="font-size:20px;color:var(--success)">Verified</div>
        <div class="stat-delta delta-up">Internal app not public</div>
      </div>
    </div>
    <div class="table-wrap" style="margin-top:18px">
      <table>
        <thead><tr><th>#</th><th>Verified Device</th><th>Certificate Serial</th><th>First Seen</th><th>Last Seen</th><th>Visits</th></tr></thead>
        <tbody id="hr-users-body">
          <tr><td colspan="6" style="text-align:center;color:var(--text-tertiary);padding:32px">No verified HR users yet. Verify a laptop through EndpointTrust first.</td></tr>
        </tbody>
      </table>
    </div>`;

  try {
    const res = await fetch('api/hr-users', {credentials: 'same-origin'});
    const data = await res.json();
    document.getElementById('hr-users-count').textContent = data.count || 0;
    const badge = document.getElementById('badge-hrusers');
    if (badge) badge.textContent = data.count || 0;
    const body = document.getElementById('hr-users-body');
    if (!data.users || !data.users.length) return;
    body.innerHTML = data.users.map((u, idx) => `
      <tr>
        <td>${idx + 1}</td>
        <td><div class="emp-cell"><div class="emp-av av-green">${(u.device_id || 'D').slice(0,2)}</div><div><div class="av-name">${u.device_id}</div><div class="av-sub">EndpointTrust verified laptop</div></div></div></td>
        <td class="mono">${String(u.certificate_serial).slice(0,28)}...</td>
        <td class="mono">${u.first_seen}</td>
        <td class="mono">${u.last_seen}</td>
        <td><span class="badge badge-active">${u.visits}</span></td>
      </tr>`).join('');
  } catch (e) {
    document.getElementById('hr-users-body').innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--danger);padding:32px">Unable to load verified HR users.</td></tr>';
  }
}

// ===== DASHBOARD =====

function renderDashboard(c) {
  const active = employees.filter(e => e.status === 'Active').length;
  const onLeave = employees.filter(e => e.status === 'On Leave').length;
  const pending = leaveRequests.filter(l => l.status === 'Pending').length;
  const suspicious = loginLogs.filter(l => l.status === 'suspicious').length;

  c.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Employees</div>
        <div class="stat-value">${employees.length}</div>
        <div class="stat-delta delta-up"><i class="ti ti-arrow-up"></i> ${employees.length} on record</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active Today</div>
        <div class="stat-value">${active}</div>
        <div class="stat-delta delta-up"><i class="ti ti-arrow-up"></i> ${Math.round(active/employees.length*100)}% attendance</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">On Leave</div>
        <div class="stat-value">${onLeave}</div>
        <div class="stat-delta delta-neutral">${pending} pending approval</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Suspicious Logins</div>
        <div class="stat-value">${suspicious}</div>
        <div class="stat-delta delta-down"><i class="ti ti-alert-triangle"></i> Needs review</div>
      </div>
    </div>

    <div class="dash-bottom">
      <div>
        <div class="section-header">
          <div class="section-title">Recent Login Activity</div>
          <button class="btn" onclick="navigateTo('activity')"><i class="ti ti-arrow-right"></i> View all</button>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Employee</th><th>Login Time</th><th>Status</th></tr></thead>
          <tbody>${loginLogs.slice(0,6).map(l=>`<tr>
            <td style="font-size:13px">${l.emp}</td>
            <td class="mono">${l.login}</td>
            <td>${l.status==='suspicious'?statusBadge('suspicious'):'<span class="badge badge-active">OK</span>'}</td>
          </tr>`).join('')}</tbody></table>
        </div>
      </div>
      <div>
        <div class="section-header">
          <div class="section-title">Pending Leave Requests</div>
          <button class="btn" onclick="navigateTo('leaves')"><i class="ti ti-arrow-right"></i> View all</button>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Employee</th><th>Type</th><th>Days</th><th>Status</th></tr></thead>
          <tbody>${leaveRequests.filter(l=>l.status==='Pending').map(l=>`<tr>
            <td style="font-size:13px">${l.emp}</td>
            <td><span class="chip">${l.type}</span></td>
            <td style="text-align:center">${l.days}</td>
            <td>${statusBadge(l.status)}</td>
          </tr>`).join('') || '<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);padding:20px">No pending requests</td></tr>'}</tbody></table>
        </div>
        <div class="section-header" style="margin-top:20px">
          <div class="section-title">Department Headcount</div>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th>Department</th><th>Employees</th><th>Active %</th></tr></thead>
          <tbody>${departments.map(d=>{
            const count = employees.filter(e=>e.dept===d.name).length;
            const activeCount = employees.filter(e=>e.dept===d.name&&e.status==='Active').length;
            const pct = count ? Math.round(activeCount/count*100) : 0;
            return`<tr><td>${d.name}</td><td>${count}</td><td>${pct}%</td></tr>`;
          }).join('')}</tbody></table>
        </div>
      </div>
    </div>`;
}

// ===== EMPLOYEES =====

let empDeptFilter = '', empStatusFilter = '';

function renderEmployees(c) {
  if (!c) c = document.getElementById('main-content');
  c.innerHTML = `
    <div class="filter-bar">
      <select class="select-sm" onchange="empDeptFilter=this.value;reRenderEmpTable()">
        <option value="">All Departments</option>
        ${[...new Set(employees.map(e=>e.dept))].map(d=>`<option ${empDeptFilter===d?'selected':''}>${d}</option>`).join('')}
      </select>
      <select class="select-sm" onchange="empStatusFilter=this.value;reRenderEmpTable()">
        <option value="">All Statuses</option>
        <option value="Active" ${empStatusFilter==='Active'?'selected':''}>Active</option>
        <option value="Inactive" ${empStatusFilter==='Inactive'?'selected':''}>Inactive</option>
        <option value="On Leave" ${empStatusFilter==='On Leave'?'selected':''}>On Leave</option>
      </select>
      <span style="font-size:12px;color:var(--text-tertiary);margin-left:4px" id="emp-count">${employees.length} employees</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th><input type="checkbox" onchange="toggleAll(this)" title="Select all"></th>
          <th>Employee</th><th>Department</th><th>Role</th><th>Status</th>
          <th>Joined</th><th>Last Login</th><th>Actions</th>
        </tr></thead>
        <tbody id="emp-table-body"></tbody>
      </table>
    </div>`;
  reRenderEmpTable();
}

function reRenderEmpTable() {
  let list = employees;
  if (empDeptFilter) list = list.filter(e => e.dept === empDeptFilter);
  if (empStatusFilter) list = list.filter(e => e.status === empStatusFilter);
  const cnt = document.getElementById('emp-count');
  if (cnt) cnt.textContent = list.length + ' employees';
  const tb = document.getElementById('emp-table-body');
  if (!tb) return;
  tb.innerHTML = list.map((e,i) => {
    const avClass = AV_COLORS[employees.indexOf(e) % AV_COLORS.length];
    return `<tr>
      <td><input type="checkbox"></td>
      <td>
        <div class="emp-cell">
          <div class="emp-av ${avClass}">${initials(e.name)}</div>
          <div>
            <div class="av-name">${e.name}</div>
            <div class="av-sub">${e.email}</div>
          </div>
        </div>
      </td>
      <td>${deptBadge(e.dept)}</td>
      <td style="color:var(--text-secondary)">${e.role}</td>
      <td>${statusBadge(e.status)}</td>
      <td class="mono" style="color:var(--text-secondary)">${e.joined}</td>
      <td class="mono" style="color:var(--text-secondary);font-size:12px">${e.lastLogin}</td>
      <td>
        <div class="row-actions row-actions-hide">
          <button class="icon-btn" onclick="viewEmployee(${e.id})" title="View profile"><i class="ti ti-eye"></i></button>
          <button class="icon-btn" onclick="showToast('Edit coming soon')" title="Edit"><i class="ti ti-edit"></i></button>
          <button class="icon-btn danger" onclick="removeEmployee(${e.id})" title="Remove"><i class="ti ti-trash"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-tertiary)">No employees found</td></tr>';
}

function toggleAll(cb) {
  document.querySelectorAll('#emp-table-body input[type=checkbox]').forEach(c => c.checked = cb.checked);
}

// ===== LOGIN ACTIVITY =====

function renderActivity(c) {
  c.innerHTML = `
    <div class="tabs">
      <div class="tab active" onclick="switchActTab(this,'all')">All Logins</div>
      <div class="tab" onclick="switchActTab(this,'suspicious')">Suspicious <span class="nav-badge" style="margin-left:4px">${loginLogs.filter(l=>l.status==='suspicious').length}</span></div>
      <div class="tab" onclick="switchActTab(this,'active')">Active Sessions <span class="chip" style="margin-left:4px">${loginLogs.filter(l=>l.logout==='—').length}</span></div>
    </div>
    <div class="filter-bar">
      <select class="select-sm" onchange="filterLogByEmp(this.value)">
        <option value="">All employees</option>
        ${[...new Set(loginLogs.map(l=>l.emp))].map(n=>`<option>${n}</option>`).join('')}
      </select>
      <button class="btn btn-danger" onclick="clearAllLogs()"><i class="ti ti-trash"></i> Clear All Logs</button>
      <button class="btn" onclick="exportLogs()"><i class="ti ti-download"></i> Export CSV</button>
    </div>
    <div id="act-all">
      <div class="table-wrap">
        <table><thead><tr>
          <th>Employee</th><th>Login Time</th><th>Logout Time</th><th>Duration</th>
          <th>IP Address</th><th>Device</th><th>Location</th><th>Status</th><th>Actions</th>
        </tr></thead>
        <tbody id="log-table-body"></tbody></table>
      </div>
    </div>
    <div id="act-suspicious" style="display:none">
      <div class="table-wrap">
        <table><thead><tr>
          <th>Employee</th><th>Timestamp</th><th>IP Address</th><th>Location</th><th>Device</th><th>Actions</th>
        </tr></thead>
        <tbody>${loginLogs.filter(l=>l.status==='suspicious').map(l=>`<tr>
          <td>${l.emp}</td>
          <td class="mono">${l.login}</td>
          <td class="mono">${l.ip}</td>
          <td style="color:var(--warning)">${l.location}</td>
          <td style="font-size:12px;color:var(--text-secondary)">${l.device}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn" onclick="showToast('Login flagged for HR review')" title="Flag"><i class="ti ti-flag"></i></button>
              <button class="icon-btn danger" onclick="deleteLog(${l.id},this)" title="Delete log"><i class="ti ti-trash"></i></button>
            </div>
          </td>
        </tr>`).join('')}</tbody></table>
      </div>
    </div>
    <div id="act-active" style="display:none">
      <div class="table-wrap">
        <table><thead><tr>
          <th>Employee</th><th>Login Time</th><th>IP Address</th><th>Device</th><th>Location</th><th>Actions</th>
        </tr></thead>
        <tbody>${loginLogs.filter(l=>l.logout==='—').map(l=>`<tr>
          <td>${l.emp}</td>
          <td class="mono">${l.login}</td>
          <td class="mono">${l.ip}</td>
          <td style="font-size:12px;color:var(--text-secondary)">${l.device}</td>
          <td style="font-size:12px">${l.location}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn danger" onclick="terminateSession(${l.id},this)" title="Terminate session"><i class="ti ti-player-stop"></i></button>
            </div>
          </td>
        </tr>`).join('')}</tbody></table>
      </div>
    </div>`;
  renderLogTable(loginLogs);
}

function renderLogTable(logs) {
  const tb = document.getElementById('log-table-body');
  if (!tb) return;
  tb.innerHTML = logs.map(l => `<tr>
    <td>${l.emp}</td>
    <td class="mono">${l.login}</td>
    <td class="mono">${l.logout}</td>
    <td><span class="chip">${l.duration}</span></td>
    <td class="mono">${l.ip}</td>
    <td style="font-size:12px;color:var(--text-secondary)">${l.device}</td>
    <td style="font-size:12px">${l.location}</td>
    <td>${l.status==='suspicious'?statusBadge('suspicious'):'<span class="badge badge-active">OK</span>'}</td>
    <td>
      <div class="row-actions row-actions-hide">
        <button class="icon-btn danger" onclick="deleteLog(${l.id},this)" title="Delete log entry"><i class="ti ti-trash"></i></button>
      </div>
    </td>
  </tr>`).join('') || '<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text-tertiary)">No logs found</td></tr>';
}

function switchActTab(el, id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  ['all','suspicious','active'].forEach(s => {
    const el2 = document.getElementById('act-'+s);
    if (el2) el2.style.display = s===id ? '' : 'none';
  });
}

function filterLogByEmp(emp) {
  const filtered = emp ? loginLogs.filter(l=>l.emp===emp) : loginLogs;
  renderLogTable(filtered);
}

function deleteLog(id, btn) {
  const idx = loginLogs.findIndex(l=>l.id===id);
  if (idx>-1) { loginLogs.splice(idx,1); btn.closest('tr').remove(); showToast('Log entry deleted'); }
}

function terminateSession(id, btn) {
  const log = loginLogs.find(l=>l.id===id);
  if (log) { log.logout = new Date().toISOString().replace('T',' ').slice(0,19); log.duration = 'Terminated'; btn.closest('tr').remove(); showToast('Session terminated'); }
}

function clearAllLogs() {
  confirm('Delete ALL login logs? This cannot be undone.', () => {
    loginLogs.length = 0;
    renderActivity(document.getElementById('main-content'));
    showToast('All logs cleared');
  });
}

function exportLogs() {
  const header = 'Employee,Login Time,Logout Time,Duration,IP Address,Device,Location,Status\n';
  const rows = loginLogs.map(l=>`${l.emp},${l.login},${l.logout},${l.duration},${l.ip},"${l.device}",${l.location},${l.status}`).join('\n');
  const blob = new Blob([header+rows], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'login_logs.csv';
  a.click();
  showToast('CSV exported');
}

// ===== ATTENDANCE =====

function renderAttendance(c) {
  const today = new Date().toISOString().split('T')[0];
  c.innerHTML = `
    <div class="filter-bar">
      <input type="date" class="form-input" style="width:170px" value="${today}" id="att-date-filter">
      <select class="select-sm" onchange="filterAttByDept(this.value)">
        <option value="">All Departments</option>
        ${[...new Set(employees.map(e=>e.dept))].map(d=>`<option>${d}</option>`).join('')}
      </select>
      <button class="btn" onclick="exportAttendance()"><i class="ti ti-download"></i> Export</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Employee</th><th>Date</th><th>Check In</th><th>Check Out</th><th>Hours</th><th>Status</th><th>Notes</th></tr></thead>
        <tbody id="att-body">${renderAttRows(attendanceData)}</tbody>
      </table>
    </div>`;
}

function renderAttRows(data) {
  return data.map(a => {
    const i = employees.findIndex(e=>e.name===a.emp);
    const avClass = AV_COLORS[i>=0?i:0];
    return `<tr>
      <td><div class="emp-cell"><div class="emp-av ${avClass}" style="width:28px;height:28px;font-size:10px">${initials(a.emp)}</div><span>${a.emp}</span></div></td>
      <td class="mono" style="color:var(--text-secondary)">${a.date}</td>
      <td class="mono">${a.checkIn}</td>
      <td class="mono">${a.checkOut}</td>
      <td><span class="chip">${a.hours}</span></td>
      <td>${statusBadge(a.status)}</td>
      <td style="font-size:12px;color:var(--text-tertiary)">${a.notes}</td>
    </tr>`;
  }).join('');
}

function filterAttByDept(dept) {
  const filtered = dept ? attendanceData.filter(a => {
    const emp = employees.find(e=>e.name===a.emp);
    return emp && emp.dept===dept;
  }) : attendanceData;
  const tb = document.getElementById('att-body');
  if (tb) tb.innerHTML = renderAttRows(filtered);
}

function exportAttendance() {
  const header = 'Employee,Date,Check In,Check Out,Hours,Status,Notes\n';
  const rows = attendanceData.map(a=>`${a.emp},${a.date},${a.checkIn},${a.checkOut},${a.hours},${a.status},"${a.notes}"`).join('\n');
  const blob = new Blob([header+rows],{type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download='attendance.csv'; a.click();
  showToast('Attendance exported');
}

// ===== PAYROLL =====

function renderPayroll(c) {
  const total = employees.reduce((s,e)=>s+e.salary,0);
  c.innerHTML = `
    <div class="stats-grid stats-grid-3">
      <div class="stat-card"><div class="stat-label">Monthly Payroll</div><div class="stat-value">${fmtSalary(Math.round(total/12))}</div><div class="stat-delta delta-up">On track</div></div>
      <div class="stat-card"><div class="stat-label">Employees Processed</div><div class="stat-value">${employees.filter(e=>e.status!=='Inactive').length}/${employees.length}</div><div class="stat-delta delta-neutral">${employees.filter(e=>e.status==='Inactive').length} skipped</div></div>
      <div class="stat-card"><div class="stat-label">Next Payroll Run</div><div class="stat-value">Jun 30</div><div class="stat-delta delta-neutral">28 days away</div></div>
    </div>
    <div class="section-header">
      <div class="section-title">Payroll Summary</div>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="exportPayroll()"><i class="ti ti-download"></i> Export</button>
        <button class="btn btn-primary" onclick="showToast('Payroll run initiated for all active employees')"><i class="ti ti-player-play"></i> Run Payroll</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Employee</th><th>Department</th><th>Base Salary</th><th>Bonus (5%)</th><th>Deductions (18%)</th><th>Net Pay</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>${employees.map((e,i)=>{
          const bonus = Math.round(e.salary*.05);
          const ded = Math.round(e.salary*.18);
          const net = e.salary+bonus-ded;
          const avClass = AV_COLORS[i%AV_COLORS.length];
          return `<tr>
            <td><div class="emp-cell"><div class="emp-av ${avClass}" style="width:28px;height:28px;font-size:10px">${initials(e.name)}</div><span>${e.name}</span></div></td>
            <td>${deptBadge(e.dept)}</td>
            <td>${fmtSalary(e.salary)}</td>
            <td style="color:var(--success)">+${fmtSalary(bonus)}</td>
            <td style="color:var(--danger)">-${fmtSalary(ded)}</td>
            <td style="font-weight:600">${fmtSalary(net)}</td>
            <td>${e.status==='Inactive'?'<span class="badge badge-inactive">Skip</span>':'<span class="badge badge-active">Process</span>'}</td>
            <td>
              <div class="row-actions row-actions-hide">
                <button class="icon-btn" onclick="showToast('Payslip sent to ${e.name}')" title="Send payslip"><i class="ti ti-send"></i></button>
                <button class="icon-btn" onclick="showToast('Payslip PDF for ${e.name}')" title="Download"><i class="ti ti-download"></i></button>
              </div>
            </td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    </div>`;
}

function exportPayroll() {
  const header = 'Employee,Department,Base Salary,Bonus,Deductions,Net Pay,Status\n';
  const rows = employees.map(e=>{
    const bonus=Math.round(e.salary*.05),ded=Math.round(e.salary*.18);
    return `${e.name},${e.dept},${e.salary},${bonus},${ded},${e.salary+bonus-ded},${e.status}`;
  }).join('\n');
  const blob=new Blob([header+rows],{type:'text/csv'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='payroll.csv';a.click();
  showToast('Payroll exported');
}

// ===== LEAVES =====

function renderLeaves(c) {
  c.innerHTML = `
    <div class="filter-bar">
      <select class="select-sm" onchange="filterLeaveStatus(this.value)">
        <option value="">All Statuses</option>
        <option value="Pending">Pending</option>
        <option value="Approved">Approved</option>
        <option value="Rejected">Rejected</option>
      </select>
      <button class="btn" onclick="showToast('New leave request form')"><i class="ti ti-plus"></i> New Request</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Employee</th><th>Type</th><th>From</th><th>To</th><th>Days</th><th>Reason</th><th>Status</th><th>Approved By</th><th>Actions</th></tr></thead>
        <tbody id="leave-body">${renderLeaveRows(leaveRequests)}</tbody>
      </table>
    </div>`;
}

function renderLeaveRows(data) {
  return data.map(l => `<tr>
    <td>${l.emp}</td>
    <td><span class="chip">${l.type}</span></td>
    <td class="mono" style="font-size:12px">${l.from}</td>
    <td class="mono" style="font-size:12px">${l.to}</td>
    <td style="text-align:center;font-weight:500">${l.days}</td>
    <td style="font-size:12px;color:var(--text-secondary);max-width:160px">${l.reason}</td>
    <td>${statusBadge(l.status)}</td>
    <td style="font-size:12px;color:var(--text-tertiary)">${l.approvedBy}</td>
    <td>
      <div class="row-actions" style="opacity:1">
        ${l.status==='Pending'
          ? `<button class="icon-btn" style="color:var(--success);border-color:#6ee7b7" onclick="approveLeave(${l.id})" title="Approve"><i class="ti ti-check"></i></button>
             <button class="icon-btn danger" onclick="rejectLeave(${l.id})" title="Reject"><i class="ti ti-x"></i></button>`
          : `<button class="icon-btn" onclick="showToast('View leave details')" title="View"><i class="ti ti-eye"></i></button>`}
      </div>
    </td>
  </tr>`).join('') || '<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--text-tertiary)">No leave requests</td></tr>';
}

function approveLeave(id) {
  const l = leaveRequests.find(x=>x.id===id);
  if (l) { l.status='Approved'; l.approvedBy='Admin'; renderLeaves(document.getElementById('main-content')); showToast(`Leave approved for ${l.emp}`); }
}

function rejectLeave(id) {
  const l = leaveRequests.find(x=>x.id===id);
  if (l) { l.status='Rejected'; renderLeaves(document.getElementById('main-content')); showToast(`Leave rejected for ${l.emp}`); }
}

function filterLeaveStatus(s) {
  const filtered = s ? leaveRequests.filter(l=>l.status===s) : leaveRequests;
  const tb = document.getElementById('leave-body');
  if (tb) tb.innerHTML = renderLeaveRows(filtered);
}

// ===== DEPARTMENTS =====

function renderDepartments(c) {
  c.innerHTML = `
    <div class="section-header">
      <div class="section-title">All Departments (${departments.length})</div>
      <button class="btn btn-primary" onclick="showToast('Add department form')"><i class="ti ti-plus"></i> Add Department</button>
    </div>
    <div class="dept-grid">
      ${departments.map(d=>{
        const count = employees.filter(e=>e.dept===d.name).length;
        const active = employees.filter(e=>e.dept===d.name&&e.status==='Active').length;
        return `<div class="dept-card">
          <div class="dept-icon"><i class="ti ${d.icon}"></i></div>
          <div class="dept-name">${d.name}</div>
          <div class="dept-count">${count} employees · ${active} active</div>
          <div style="font-size:12px;color:var(--text-tertiary);margin-top:4px">Head: ${d.head} · Budget: ${d.budget}</div>
          <div class="dept-actions">
            <button class="btn" style="font-size:12px;padding:6px 10px" onclick="showToast('View ${d.name} team')"><i class="ti ti-users"></i> View Team</button>
            <button class="btn" style="font-size:12px;padding:6px 10px" onclick="showToast('Edit ${d.name}')"><i class="ti ti-edit"></i></button>
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

// ===== ROLES =====

function renderRoles(c) {
  c.innerHTML = `
    <div class="section-header">
      <div class="section-title">Roles & Permissions</div>
      <button class="btn btn-primary" onclick="showToast('Create role form')"><i class="ti ti-plus"></i> New Role</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Role</th><th>Employees</th><th>Permissions</th><th>Last Updated</th><th>Actions</th></tr></thead>
        <tbody>${roles.map(r=>`<tr>
          <td style="font-weight:500">${r.role}</td>
          <td><span class="chip">${r.count} users</span></td>
          <td>${r.perms.map(p=>`<span class="chip" style="margin-right:3px;margin-bottom:2px">${p}</span>`).join('')}</td>
          <td class="mono" style="color:var(--text-tertiary);font-size:12px">${r.updated}</td>
          <td>
            <div class="row-actions row-actions-hide">
              <button class="icon-btn" onclick="showToast('Edit ${r.role} role')"><i class="ti ti-edit"></i></button>
            </div>
          </td>
        </tr>`).join('')}</tbody>
      </table>
    </div>`;
}

// ===== SETTINGS =====

function renderSettings(c) {
  c.innerHTML = `
    <div style="max-width:560px">
      <div class="section-title" style="margin-bottom:16px">Security & Session Settings</div>
      <div class="settings-group">
        <div class="settings-row">
          <div><div class="settings-label">Session timeout</div><div class="settings-sub">Auto-logout after inactivity</div></div>
          <select class="select-sm"><option>30 minutes</option><option>1 hour</option><option>4 hours</option><option>Never</option></select>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Two-factor authentication</div><div class="settings-sub">Require 2FA for all HR users</div></div>
          <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Suspicious login alerts</div><div class="settings-sub">Email HR on unusual login attempts</div></div>
          <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Login log retention</div><div class="settings-sub">How long to keep login records</div></div>
          <select class="select-sm"><option>90 days</option><option selected>180 days</option><option>1 year</option><option>Forever</option></select>
        </div>
      </div>

      <div class="section-title" style="margin-bottom:16px">Notifications</div>
      <div class="settings-group">
        <div class="settings-row">
          <div><div class="settings-label">Leave request notifications</div><div class="settings-sub">Email on new leave requests</div></div>
          <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Payroll reminders</div><div class="settings-sub">Remind 3 days before payroll run</div></div>
          <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">New employee alerts</div><div class="settings-sub">Notify managers on new hires</div></div>
          <label class="toggle"><input type="checkbox"><span class="toggle-slider"></span></label>
        </div>
      </div>

      <div class="section-title" style="margin-bottom:16px">Company Details</div>
      <div class="settings-group">
        <div class="settings-row" style="display:block">
          <div class="form-row" style="margin-bottom:0">
            <label class="form-label">Company Name</label>
            <input class="form-input" value="ACME Corporation" style="max-width:320px">
          </div>
        </div>
        <div class="settings-row" style="display:block">
          <div class="form-row" style="margin-bottom:0">
            <label class="form-label">HR Contact Email</label>
            <input class="form-input" type="email" value="hr@acme.com" style="max-width:320px">
          </div>
        </div>
      </div>

      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="btn btn-primary" onclick="showToast('Settings saved successfully')"><i class="ti ti-check"></i> Save Changes</button>
        <button class="btn" onclick="showToast('Settings reset to defaults')">Reset to defaults</button>
      </div>
    </div>`;
}
