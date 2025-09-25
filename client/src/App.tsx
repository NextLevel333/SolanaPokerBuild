
import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import PokerTable from './components/PokerTable';
import AdminLogin from './admin/AdminLogin';
import AdminDashboard from './admin/AdminDashboard';
export default function App(){ return (<BrowserRouter><Routes><Route path='/' element={<PokerTable/>} /><Route path='/admin/login' element={<AdminLogin/>} /><Route path='/admin/dashboard' element={<AdminDashboard/>} /></Routes></BrowserRouter>); }
