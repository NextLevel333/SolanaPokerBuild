
import React, { useState } from 'react';
export default function AdminLogin(){ const [u,setU]=useState('admin'); const [p,setP]=useState('changeme'); return (<div style={{padding:20}}><h2>Admin Login</h2><input value={u} onChange={e=>setU(e.target.value)} /><input value={p} onChange={e=>setP(e.target.value)} /><button>Login</button></div>); }
