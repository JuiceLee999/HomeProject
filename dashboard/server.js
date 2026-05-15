const express = require('express');
const helmet  = require('helmet');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT      || 3005;
const BASE = process.env.BASE_PATH || '/dash';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ['https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(BASE, express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.redirect(BASE));

app.listen(PORT, () => console.log(`Dashboard running on port ${PORT} at ${BASE}`));
