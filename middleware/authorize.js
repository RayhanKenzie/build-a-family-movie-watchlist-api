export function authorizeModification(req, res, next) {
  // FreeCodeCamp rule: respond 403 if req.user.role is not "parent", 
  // or if req.user.role is not "child" and req.params.userId is not the same as req.user.id.
  if (req.user.role !== "parent" && (req.user.role !== "child" || req.params.userId != req.user.id)) {
    return res.status(403).json({ error: "Access denied" });
  }
  
  next();
}
