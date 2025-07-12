const express = require('express');
const router = express.Router();
const friend = require('../controllers/friendController');

router.post('/send', friend.sendRequest);
router.get('/', friend.getPendingRequests);
router.post('/accept/:id', friend.acceptRequest);
router.post('/reject/:id', friend.rejectRequest);

module.exports = router;
