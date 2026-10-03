// MV3 service worker. All logic lives in bridge.js so it can be tested with fakes.
import { createBackground } from './bridge.js';

createBackground(chrome).install();
