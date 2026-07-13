// ===== SAMPLE DATA =====

const AV_COLORS = ['av-blue','av-teal','av-coral','av-purple','av-pink','av-amber','av-green'];

let employees = [
  {id:1,name:'Alex Rivera',email:'alex@corp.com',dept:'Engineering',role:'Senior Developer',status:'Active',joined:'2022-03-15',lastLogin:'2026-06-02 09:14',phone:'+1 555 0110',salary:95000,type:'Full-time'},
  {id:2,name:'Sarah Chen',email:'sarah@corp.com',dept:'Marketing',role:'Marketing Manager',status:'Active',joined:'2021-07-01',lastLogin:'2026-06-02 08:47',phone:'+1 555 0111',salary:88000,type:'Full-time'},
  {id:3,name:'Marcus Johnson',email:'marcus@corp.com',dept:'Finance',role:'Financial Analyst',status:'Active',joined:'2023-01-10',lastLogin:'2026-06-01 17:02',phone:'+1 555 0112',salary:72000,type:'Full-time'},
  {id:4,name:'Priya Patel',email:'priya@corp.com',dept:'Engineering',role:'Junior Developer',status:'Active',joined:'2024-02-20',lastLogin:'2026-06-02 09:30',phone:'+1 555 0113',salary:65000,type:'Full-time'},
  {id:5,name:'Tom Wallace',email:'tom@corp.com',dept:'HR',role:'HR Coordinator',status:'On Leave',joined:'2020-11-05',lastLogin:'2026-05-28 12:00',phone:'+1 555 0114',salary:60000,type:'Full-time'},
  {id:6,name:'Mei Lin',email:'mei@corp.com',dept:'Sales',role:'Account Executive',status:'Active',joined:'2022-09-12',lastLogin:'2026-06-02 08:05',phone:'+1 555 0115',salary:75000,type:'Full-time'},
  {id:7,name:'David Kim',email:'david@corp.com',dept:'Engineering',role:'Tech Lead',status:'Active',joined:'2019-04-01',lastLogin:'2026-06-02 07:58',phone:'+1 555 0116',salary:120000,type:'Full-time'},
  {id:8,name:'Lisa Torres',email:'lisa@corp.com',dept:'Marketing',role:'UI Designer',status:'Inactive',joined:'2023-06-15',lastLogin:'2026-05-15 10:00',phone:'+1 555 0117',salary:68000,type:'Full-time'},
  {id:9,name:'Omar Hassan',email:'omar@corp.com',dept:'Sales',role:'Sales Director',status:'Active',joined:'2020-01-20',lastLogin:'2026-06-02 10:05',phone:'+1 555 0118',salary:105000,type:'Full-time'},
  {id:10,name:'Nina Reyes',email:'nina@corp.com',dept:'Operations',role:'Operations Manager',status:'Active',joined:'2021-03-08',lastLogin:'2026-06-02 09:00',phone:'+1 555 0119',salary:82000,type:'Full-time'},
];

let loginLogs = [
  {id:1,emp:'Alex Rivera',login:'2026-06-02 09:14:22',logout:'—',duration:'Active',ip:'192.168.1.10',device:'Chrome 124 / macOS',status:'success',location:'New York, US'},
  {id:2,emp:'Sarah Chen',login:'2026-06-02 08:47:05',logout:'—',duration:'Active',ip:'10.0.0.42',device:'Firefox 126 / Windows',status:'success',location:'Chicago, US'},
  {id:3,emp:'Priya Patel',login:'2026-06-02 09:30:11',logout:'—',duration:'Active',ip:'192.168.1.55',device:'Safari / iOS 17',status:'success',location:'San Francisco, US'},
  {id:4,emp:'David Kim',login:'2026-06-02 07:58:44',logout:'—',duration:'Active',ip:'192.168.1.12',device:'Chrome 124 / macOS',status:'success',location:'Austin, US'},
  {id:5,emp:'Mei Lin',login:'2026-06-02 08:05:33',logout:'—',duration:'Active',ip:'10.0.1.20',device:'Edge 124 / Windows',status:'success',location:'Seattle, US'},
  {id:6,emp:'Omar Hassan',login:'2026-06-02 10:05:00',logout:'—',duration:'Active',ip:'192.168.1.77',device:'Chrome 124 / Windows',status:'success',location:'Dallas, US'},
  {id:7,emp:'Nina Reyes',login:'2026-06-02 09:00:00',logout:'—',duration:'Active',ip:'192.168.1.90',device:'Chrome 124 / macOS',status:'success',location:'Miami, US'},
  {id:8,emp:'Marcus Johnson',login:'2026-06-01 17:02:15',logout:'2026-06-01 18:30:44',duration:'1h 28m',ip:'192.168.1.33',device:'Chrome 124 / Linux',status:'success',location:'Boston, US'},
  {id:9,emp:'Tom Wallace',login:'2026-05-28 12:00:00',logout:'2026-05-28 13:15:22',duration:'1h 15m',ip:'203.0.113.55',device:'Chrome 120 / Windows',status:'suspicious',location:'Unknown, VPN'},
  {id:10,emp:'Lisa Torres',login:'2026-05-15 10:00:00',logout:'2026-05-15 12:30:00',duration:'2h 30m',ip:'192.168.1.88',device:'Safari / macOS',status:'success',location:'New York, US'},
  {id:11,emp:'Alex Rivera',login:'2026-06-01 09:05:00',logout:'2026-06-01 18:00:00',duration:'8h 55m',ip:'192.168.1.10',device:'Chrome 124 / macOS',status:'success',location:'New York, US'},
  {id:12,emp:'Tom Wallace',login:'2026-05-27 23:45:00',logout:'2026-05-28 00:30:00',duration:'45m',ip:'185.220.101.5',device:'Unknown Browser',status:'suspicious',location:'Unknown'},
];

let attendanceData = [
  {emp:'Alex Rivera',date:'2026-06-02',checkIn:'09:14',checkOut:'—',hours:'Active',status:'Present',notes:''},
  {emp:'Sarah Chen',date:'2026-06-02',checkIn:'08:47',checkOut:'—',hours:'Active',status:'Present',notes:''},
  {emp:'Marcus Johnson',date:'2026-06-02',checkIn:'—',checkOut:'—',hours:'0',status:'Absent',notes:'No notification'},
  {emp:'Priya Patel',date:'2026-06-02',checkIn:'09:30',checkOut:'—',hours:'Active',status:'Present',notes:''},
  {emp:'Tom Wallace',date:'2026-06-02',checkIn:'—',checkOut:'—',hours:'0',status:'On Leave',notes:'Medical leave approved'},
  {emp:'Mei Lin',date:'2026-06-02',checkIn:'08:05',checkOut:'—',hours:'Active',status:'Present',notes:'Early start'},
  {emp:'David Kim',date:'2026-06-02',checkIn:'07:58',checkOut:'—',hours:'Active',status:'Present',notes:'Early arrival'},
  {emp:'Lisa Torres',date:'2026-06-02',checkIn:'—',checkOut:'—',hours:'0',status:'Inactive',notes:'Account deactivated'},
  {emp:'Omar Hassan',date:'2026-06-02',checkIn:'10:05',checkOut:'—',hours:'Active',status:'Present',notes:''},
  {emp:'Nina Reyes',date:'2026-06-02',checkIn:'09:00',checkOut:'—',hours:'Active',status:'Present',notes:''},
];

let leaveRequests = [
  {id:1,emp:'Tom Wallace',type:'Sick Leave',from:'2026-05-28',to:'2026-06-03',days:5,reason:'Medical procedure recovery',status:'Approved',approvedBy:'Admin'},
  {id:2,emp:'Priya Patel',type:'Annual Leave',from:'2026-06-15',to:'2026-06-20',days:4,reason:'Family vacation',status:'Pending',approvedBy:'—'},
  {id:3,emp:'Mei Lin',type:'Personal',from:'2026-06-10',to:'2026-06-10',days:1,reason:'Personal appointment',status:'Pending',approvedBy:'—'},
  {id:4,emp:'Sarah Chen',type:'Annual Leave',from:'2026-07-01',to:'2026-07-07',days:5,reason:'Summer holiday',status:'Approved',approvedBy:'Admin'},
  {id:5,emp:'David Kim',type:'Work From Home',from:'2026-06-05',to:'2026-06-07',days:3,reason:'Home renovation',status:'Approved',approvedBy:'Admin'},
];

const departments = [
  {name:'Engineering',icon:'ti-code',head:'David Kim',headcount:3,budget:'$450K'},
  {name:'Marketing',icon:'ti-speakerphone',head:'Sarah Chen',headcount:2,budget:'$180K'},
  {name:'Finance',icon:'ti-coin',head:'Marcus Johnson',headcount:1,budget:'$120K'},
  {name:'HR',icon:'ti-users',head:'Tom Wallace',headcount:1,budget:'$90K'},
  {name:'Sales',icon:'ti-chart-line',head:'Omar Hassan',headcount:2,budget:'$250K'},
  {name:'Operations',icon:'ti-settings',head:'Nina Reyes',headcount:1,budget:'$200K'},
];

const roles = [
  {role:'HR Manager',count:1,perms:['Full Access','User Management','Payroll','Reports'],updated:'2026-01-10'},
  {role:'Manager',count:4,perms:['View Reports','Approve Leaves','View Team Payroll'],updated:'2026-02-14'},
  {role:'Employee',count:18,perms:['View Own Profile','Request Leave','View Payslip'],updated:'2025-12-01'},
  {role:'Intern',count:2,perms:['View Own Profile'],updated:'2026-03-05'},
];

let nextEmpId = 11;
let nextLogId = 13;
