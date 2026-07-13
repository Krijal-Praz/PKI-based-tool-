
// ===== ENDPOINTTRUST VERIFIED ENTRY =====

async function recordEndpointTrustVerifiedEntry() {
  try {
    await fetch('api/verified-entry', {method: 'POST', credentials: 'same-origin'});
    await refreshHRUsersBadge();
  } catch (e) {
    console.log('EndpointTrust verified-entry check skipped:', e);
  }
}

async function refreshHRUsersBadge() {
  try {
    const res = await fetch('api/hr-users', {credentials: 'same-origin'});
    const data = await res.json();
    const badge = document.getElementById('badge-hrusers');
    if (badge) badge.textContent = data.count || 0;
  } catch (e) {}
}

// ===== AUTH =====

function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const pass = document.getElementById('login-pass').value.trim();
  if (!email || !pass) { showToast('Please enter credentials', true); return; }
  document.getElementById('admin-name').textContent = email.split('@')[0].replace(/^\w/,c=>c.toUpperCase());
  const ts = new Date().toISOString().replace('T',' ').slice(0,19);
  loginLogs.unshift({id:nextLogId++,emp:'Admin',login:ts,logout:'—',duration:'Active',ip:'127.0.0.1',device:'This Browser',status:'success',location:'Local'});
  document.getElementById('login-page').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');
  navigateTo('dashboard');
  showToast('Welcome back, ' + email.split('@')[0]);
}

function doLogout() {
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-page').classList.remove('hidden');
  showToast('Signed out successfully');
}

// ===== NAVIGATION =====

const PAGE_TITLES = {
  dashboard:'Dashboard', employees:'Employees', hrusers:'HR Users', activity:'Login Activity',
  attendance:'Attendance', payroll:'Payroll', leaves:'Leave Requests',
  departments:'Departments', roles:'Roles & Access', settings:'Settings'
};

function navigateTo(page) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navEl = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (navEl) navEl.classList.add('active');
  document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;
  const content = document.getElementById('main-content');
  content.innerHTML = '';
  const renderers = {
    dashboard: renderDashboard, employees: renderEmployees, hrusers: renderHRUsers,
    activity: renderActivity, attendance: renderAttendance,
    payroll: renderPayroll, leaves: renderLeaves,
    departments: renderDepartments, roles: renderRoles, settings: renderSettings
  };
  if (renderers[page]) renderers[page](content);
}

document.addEventListener('DOMContentLoaded', () => {
  recordEndpointTrustVerifiedEntry();
  document.querySelectorAll('.nav-item').forEach(n => {
    n.addEventListener('click', () => navigateTo(n.dataset.page));
  });
  document.querySelectorAll('.modal-backdrop').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
  });
});

// ===== MODALS =====

function openModal(id) { document.getElementById('modal-'+id).classList.add('open'); }
function closeModal(id) { document.getElementById('modal-'+id).classList.remove('open'); }

function confirm(msg, cb) {
  document.getElementById('confirm-msg').textContent = msg;
  const btn = document.getElementById('confirm-ok');
  btn.onclick = () => { cb(); closeModal('confirm'); };
  openModal('confirm');
}

// ===== ADD EMPLOYEE =====

function addEmployee() {
  const fname = document.getElementById('new-fname').value.trim();
  const lname = document.getElementById('new-lname').value.trim();
  const email = document.getElementById('new-email').value.trim();
  if (!fname || !lname || !email) { showToast('Name and email are required', true); return; }
  const emp = {
    id: nextEmpId++,
    name: fname + ' ' + lname,
    email,
    dept: document.getElementById('new-dept').value,
    role: document.getElementById('new-role').value || 'Employee',
    status: 'Active',
    joined: document.getElementById('new-date').value || new Date().toISOString().split('T')[0],
    lastLogin: '—',
    phone: document.getElementById('new-phone').value || '—',
    salary: parseInt(document.getElementById('new-salary').value) || 0,
    type: document.getElementById('new-type').value,
  };
  employees.push(emp);
  closeModal('add-employee');
  ['new-fname','new-lname','new-email','new-phone','new-role','new-salary'].forEach(id => document.getElementById(id).value = '');
  showToast(emp.name + ' added successfully');
  navigateTo('employees');
}

// ===== VIEW EMPLOYEE =====

function viewEmployee(id) {
  const e = employees.find(x => x.id === id);
  if (!e) return;
  const i = employees.indexOf(e);
  const avClass = AV_COLORS[i % AV_COLORS.length];
  document.getElementById('emp-profile-body').innerHTML = `
    <div class="profile-hero">
      <div class="profile-av ${avClass}" style="width:60px;height:60px;font-size:18px">${initials(e.name)}</div>
      <div style="flex:1">
        <div style="font-size:18px;font-weight:600">${e.name}</div>
        <div style="font-size:13px;color:var(--text-tertiary)">${e.role} · ${e.dept}</div>
        <div style="margin-top:6px">${statusBadge(e.status)}</div>
      </div>
    </div>
    <div class="profile-fields">
      <div class="pf-item"><div class="pf-label">Email</div><div class="pf-value">${e.email}</div></div>
      <div class="pf-item"><div class="pf-label">Phone</div><div class="pf-value">${e.phone}</div></div>
      <div class="pf-item"><div class="pf-label">Department</div><div class="pf-value"><span class="badge badge-dept">${e.dept}</span></div></div>
      <div class="pf-item"><div class="pf-label">Employment type</div><div class="pf-value">${e.type}</div></div>
      <div class="pf-item"><div class="pf-label">Joined</div><div class="pf-value">${e.joined}</div></div>
      <div class="pf-item"><div class="pf-label">Base salary</div><div class="pf-value">$${e.salary.toLocaleString()}</div></div>
      <div class="pf-item" style="grid-column:1/-1"><div class="pf-label">Last login</div><div class="pf-value mono">${e.lastLogin}</div></div>
    </div>`;
  openModal('view-emp');
}

// ===== REMOVE EMPLOYEE =====

function removeEmployee(id) {
  const e = employees.find(x => x.id === id);
  if (!e) return;
  confirm(`Remove ${e.name} from the system? This cannot be undone.`, () => {
    employees = employees.filter(x => x.id !== id);
    showToast(e.name + ' removed');
    navigateTo('employees');
  });
}

// ===== GLOBAL SEARCH =====

function globalSearch(q) {
  navigateTo('employees');
  setTimeout(() => {
    const rows = document.querySelectorAll('#emp-table-body tr');
    const lq = q.toLowerCase();
    rows.forEach(r => {
      r.style.display = r.textContent.toLowerCase().includes(lq) ? '' : 'none';
    });
  }, 50);
}

// ===== HELPERS =====

function initials(name) {
  return name.split(' ').map(n => n[0]).join('').slice(0,2).toUpperCase();
}

function statusBadge(s) {
  const map = {
    'Active':'badge-active','Inactive':'badge-inactive','On Leave':'badge-leave',
    'Approved':'badge-approved','Pending':'badge-pending','Rejected':'badge-rejected',
    'Present':'badge-present','Absent':'badge-absent','suspicious':'badge-suspicious'
  };
  const dots = {'Active':'dot-green','Inactive':'dot-gray','On Leave':'dot-amber','Present':'dot-green','Absent':'dot-red'};
  const cls = map[s] || 'badge-inactive';
  const dot = dots[s] ? `<span class="dot ${dots[s]}"></span>` : '';
  return `<span class="badge ${cls}">${dot}${s}</span>`;
}

function deptBadge(d) { return `<span class="badge badge-dept">${d}</span>`; }

function showToast(msg, isError=false) {
  const t = document.getElementById('toast');
  document.getElementById('toast-msg').textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '');
  t.querySelector('.toast-icon').className = 'ti ' + (isError ? 'ti-alert-triangle' : 'ti-check') + ' toast-icon';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

function fmtSalary(n) { return '$' + Number(n).toLocaleString(); }
