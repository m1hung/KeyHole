import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Popup } from './Popup.tsx';
import './popup.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root container missing.');
createRoot(container).render(
  <StrictMode>
    <Popup />
  </StrictMode>,
);
