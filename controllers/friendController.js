const FriendRequest = require("../models/friensRequest");
const User = require("../user");
const Application = require("../models/Application");
const Job = require("../models/Job");

exports.sendRequest = async (req, res) => {
  try {
    if (!req.user) {
      console.log('User not authenticated');
      return res.status(401).send('User not logged in');
    }

    const from = req.user._id;
    const { toId } = req.body;

    console.log("Friend request sent from:", from);
    console.log("Friend request sent to  :", toId);

    if (from.toString() === toId) return res.send("Cannot friend yourself.");

    const exists = await FriendRequest.findOne({ from, to: toId, status: 'pending' });
    if (exists) return res.send("Request already sent");

    await FriendRequest.create({ from, to: toId });
    res.redirect('/');
  } catch (err) {
    console.log("Error in sending request:", err);
    res.send("Error sending request");
  }
};



exports.getPendingRequests = async (req, res) => {
  const requests = await FriendRequest.find({ to: req.user._id, status: 'pending' }).populate('from');
  
  // Get job applications where the user has been selected
  const selectedApplications = await Application.find({ 
    musician: req.user._id, 
    status: 'selected' 
  }).populate('job', 'title');
  
  res.render('requests', { requests, selectedApplications, user: req.user });
};

exports.acceptRequest = async (req, res) => {
  try {
    const requestId = req.params.id;

    const request = await FriendRequest.findById(requestId);
    if (!request || request.status !== 'pending') {
      return res.send('Invalid or already accepted');
    }


    await Promise.all([
      User.findByIdAndUpdate(request.from, { $addToSet: { friends: request.to } }),
      User.findByIdAndUpdate(request.to, { $addToSet: { friends: request.from } }),
      FriendRequest.findByIdAndUpdate(requestId, { status: 'accepted' })
    ]);

    res.redirect('/requests/');
  } catch (err) {
    console.error(err);
    res.send('Error accepting request');
  }
};


exports.rejectRequest = async (req, res) => {
  await FriendRequest.findByIdAndUpdate(req.params.id, { status: 'rejected' });
  res.redirect('/requests');
};
