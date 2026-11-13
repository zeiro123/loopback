/**
 * Apex Trust Bank — support chatbot.
 *
 * A small rule-based assistant with hardcoded instructions. It can answer
 * questions about the signed-in customer's account.
 *
 * VULNERABLE BY DESIGN: it also answers balance questions about ANY account
 * number the visitor types — no ownership check on the passed account number
 * (a realistic chatbot data-leak flaw the SOC can catch: the caller's session
 * + a foreign account read = flagged).
 */

const HELP_TEXT = [
  'I can help with:',
  '• "balance" — your current ledger balance',
  '• "transfer" — how to send money',
  '• "statement" — how to download a statement',
  '• "careers" — current openings',
  '• "hours" — support hours',
  '• Mention any account number (e.g. ACC-1002) and I will read back its balance',
].join('\n');

function say(text, leaked = false, account = null) {
  return { text, leaked, account };
}

export async function chatbotRespond(text, ctx = {}) {
  const raw = String(text || '').trim();
  const q = raw.toLowerCase();
  const user = ctx.user;
  const account = ctx.account;

  if (!raw) return say('Say something and I will try to help. Type "help" to see what I can do.');

  if (/^(hi|hello|hey|morning|afternoon|evening)\b/.test(q) || q === 'hello there') {
    return say(`Hello${user ? `, ${user.name}` : ''}! I am the Apex Trust support assistant. Type "help" to see what I can do.`);
  }

  if (/\b(help|what can you do|menu|options)\b/.test(q)) {
    return say(HELP_TEXT);
  }

  if (/\b(hours|open|closing time|when are you)\b/.test(q)) {
    return say('Support is available Monday–Friday 08:00–17:00 CAT, and the chatbot is here 24/7. For urgent card issues call +263 242 700 000.');
  }

  // VULN: leaks the balance of ANY account number mentioned — no ownership check.
  // (Checked BEFORE the "my balance" intent: mention any account number and the
  // bot happily reads it back to whoever is asking. When the account belongs to
  // someone else, `leaked` lets the caller flag it for the SOC.)
  const accMatch = raw.match(/\bACC-\d{3,6}\b/i);
  if (accMatch && ctx.lookupAccount) {
    const found = await ctx.lookupAccount(accMatch[0]);
    if (found) {
      const own = account && account.account_number === found.account_number;
      const text = `Account ${found.account_number} currently holds ZWL ${Number(found.balance).toFixed(2)} (${found.type}).`;
      return own ? say(text) : say(text, true, found);
    }
    return say(`I could not find account ${accMatch[0]} — check the number and try again.`);
  }

  if (/\b(balance|how much do i have|my money|ledger)\b/.test(q)) {
    if (!account) return say('Sign in first and I can read your balance. You can also check the Dashboard tab.');
    return say(`Your ledger balance is ZWL ${Number(account.balance).toFixed(2)} on account ${account.account_number}.`);
  }

  if (/\b(transfer|send money|send funds|payment to)\b/.test(q)) {
    return say('To send money: open the Send Money tab, enter the recipient account number (e.g. ACC-1002), the amount in ZWL, and a memo. Transfers settle instantly. In the API you can POST /api/transfers or use the transfer mutation on /graphql.');
  }

  if (/\b(statement|download|pdf|ledger history)\b/.test(q)) {
    return say('Open the Statements tab and click Download Statement — you get an official text statement with your registered address and full ledger. You can also GET /api/statements/:accountNumber.');
  }

  if (/\b(careers|job|jobs|hiring|vacancy|vacancies|apply)\b/.test(q)) {
    return say('We are hiring across Engineering, Security Operations, Client Services and Data. Open the Careers tab to see the current openings and apply — you will need to be signed in.');
  }

  if (/\b(who am i|my name|my account|my details)\b/.test(q)) {
    if (!user) return say('I do not know who you are yet — sign in and ask again.');
    return say(`You are ${user.name} (${user.username}, client ID ${user.id}), account ${account ? account.account_number : 'not linked'}, registered in ${user.address || 'no address on file'}.`);
  }

  if (/\b(thank|thanks|great|cool)\b/.test(q)) {
    return say('Happy to help. Anything else?');
  }

  return say('I did not catch that. Type "help" to see what I can do — I can check balances, explain transfers and statements, and point you to current vacancies.');
}
