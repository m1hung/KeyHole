import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Options } from './Options.tsx';
import '../../../app/src/styles.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root container missing.');
createRoot(container).render(
  <StrictMode>
    <Options />
  </StrictMode>,
);
