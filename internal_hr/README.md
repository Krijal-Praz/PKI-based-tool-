# PeopleHub — HR Portal

A fully functional standalone HR portal built with HTML, CSS, and vanilla JavaScript. No frameworks, no build tools, no server required.

## Quick Start

1. Unzip the folder
2. Open `index.html` in any modern browser
3. Login with: `admin@company.com` / `password`

That's it. No installation needed.

---

## Features

### Dashboard
- Live stats: total employees, active today, on leave, suspicious logins
- Recent login activity snapshot
- Pending leave requests
- Department headcount breakdown

### Employees
- Full employee roster with search and filters (department, status)
- Add new employee via form
- View detailed profile modal
- Remove employee with confirmation dialog
- Bulk checkbox selection

### Login Activity
- All login timestamps with IP, device, location
- Delete individual log entries
- Suspicious logins tab — flagged for review
- Active sessions tab — terminate sessions
- Clear all logs
- Export to CSV

### Attendance
- Daily check-in/check-out tracking
- Filter by department
- Status: Present / Absent / On Leave / Inactive
- Export to CSV

### Payroll
- Salary overview with bonus (5%) and deductions (18%)
- Net pay per employee
- Send payslip action
- Run payroll button
- Export to CSV

### Leave Requests
- Approve / Reject pending requests
- Filter by status
- Full leave history

### Departments
- Card view per department
- Headcount, head, budget
- View team drill-down

### Roles & Access
- Permission sets per role
- HR Manager / Manager / Employee / Intern

### Settings
- Session timeout configuration
- 2FA toggle
- Suspicious login alerts
- Log retention period
- Notification preferences
- Company details

---

## File Structure

```
hr-portal/
├── index.html          ← Main app entry point
├── css/
│   └── style.css       ← All styles
├── js/
│   ├── data.js         ← Sample data (employees, logs, etc.)
│   ├── app.js          ← Auth, navigation, modals, utilities
│   └── pages.js        ← Page renderers for each section
└── README.md
```

## Customizing Data

Edit `js/data.js` to change:
- `employees` array — add/edit employee records
- `loginLogs` array — login history
- `attendanceData` — attendance records
- `leaveRequests` — leave history
- `departments` — department list
- `roles` — role definitions

## Making It Production-Ready

To connect a real backend:
1. Replace the `employees`, `loginLogs` etc. arrays with `fetch()` calls to your API
2. Replace `doLogin()` with a real auth endpoint + JWT storage
3. Replace data mutations (addEmployee, removeEmployee, etc.) with API POST/DELETE calls

Suggested stack: Node.js + Express + PostgreSQL, or any REST/GraphQL backend.

---

Built with: HTML5 · CSS3 · Vanilla JS · Tabler Icons · DM Sans font
