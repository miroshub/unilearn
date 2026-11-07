// Adds a person to UniLearn and sends them a Clerk invitation email.
// Used to create the first admin (Phase 2). After that, admins invite people from the website (Phase 4).
// Usage: npm run add-user --prefix server -- <admin|instructor|student> <email> "<Full Name>"
const mongoose = require('mongoose');
const { clerkClient } = require('@clerk/express');
const { connectToDatabase } = require('../db');
const { User } = require('../models');

// Read the command-line words, save the user, then create the Clerk invitation
async function addUser() {
  const [role, email, ...nameWords] = process.argv.slice(2);
  const name = nameWords.join(' ');
  if (!['admin', 'instructor', 'student'].includes(role) || !email || !name) {
    console.log('Usage: npm run add-user --prefix server -- <admin|instructor|student> <email> "<Full Name>"');
    process.exit(1);
  }

  await connectToDatabase();
  const user = await User.create({ email, name, role });

  try {
    // 🔒 SECURITY 7.5.4 — No public sign-up: people join only through an invitation (OWASP A07)
    const invitation = await clerkClient.invitations.createInvitation({
      emailAddress: user.email,
      redirectUrl: process.env.APP_URL || 'http://localhost:5173',
    });
    console.log(`Added ${role} ${user.email}. Clerk has emailed them an invitation.`);
    console.log(`Invitation link (same as in the email): ${invitation.url}`);
  } catch (err) {
    // If Clerk refused, don't leave a half-created user behind
    await user.deleteOne();
    throw err;
  }

  await mongoose.disconnect();
}

addUser().catch((err) => {
  console.error('Could not add user:', err.errors?.[0]?.longMessage || err.message);
  process.exit(1);
});
