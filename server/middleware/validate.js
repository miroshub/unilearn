// Checks on the shape of request bodies, before a route uses them.
const { logWarning } = require('../logger');

// 🔒 SECURITY 7.2.3 — Request body may only contain the fields this route expects (OWASP A03)
// Stops "mass assignment": e.g. a user sending { "role": "admin" } to a route that doesn't take a role.
// Example: router.patch('/:id/role', allowFields('role'), changeRole)
function allowFields(...allowedNames) {
  return (req, res, next) => {
    const body = req.body;
    const isPlainObject = body !== null && typeof body === 'object' && !Array.isArray(body);
    const unknownNames = isPlainObject ? Object.keys(body).filter((name) => !allowedNames.includes(name)) : [];

    if (!isPlainObject || unknownNames.length > 0) {
      logWarning('Unexpected fields in request', { ip: req.ip, path: req.baseUrl + req.path, unknownNames });
      return res.status(400).json({ error: 'Bad request' });
    }
    next();
  };
}

module.exports = { allowFields };
