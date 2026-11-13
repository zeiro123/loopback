/**
 * Loopback target — Apex Trust Bank GraphQL API.
 *
 * Same bank, same PostgreSQL data, second API surface. Deliberately vulnerable:
 * any user's details/API key by id, any account/statement by number, any job
 * application by id, and the same business-logic flaws on the transfer mutation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import { createYoga, createSchema } from 'graphql-yoga';
import { setOperation, setParams, setResourceOwner, setMeta } from './trace.js';
import {
  getUserById, getAccountByNumber, getAccountByUserId, getTransactions,
  createTransaction, debit, credit, getUserByUsername, createUser,
  createSession, safeUser, buildStatement,
  listBlogPosts, getBlogPost, listComments, addComment,
  listJobs, createApplication, getApplication,
  saveChat,
} from './db.js';
import { chatbotRespond } from './chatbot.js';

const typeDefs = /* GraphQL */ `
  type User {
    id: Int!
    username: String!
    name: String!
    email: String!
    address: String
    phone: String
    occupation: String
    apiKey: String!
  }
  type Account {
    accountNumber: String!
    type: String!
    balance: Float!
    currency: String!
    ownerUserId: Int!
    transactions: [Transaction!]!
  }
  type Transaction {
    id: Int!
    description: String
    amount: Float!
    type: String!
    createdAt: String!
  }
  type Statement {
    accountNumber: String!
    ownerName: String!
    ownerEmail: String!
    address: String!
    balance: Float!
    currency: String!
    statementId: String!
    textDocument: String!
  }
  type BlogPost {
    id: Int!
    title: String!
    slug: String!
    excerpt: String
    body: String
    authorName: String
    publishedAt: String!
    commentCount: Int!
  }
  type BlogComment {
    id: Int!
    authorName: String
    body: String!
    createdAt: String!
  }
  type Job {
    id: Int!
    title: String!
    department: String
    location: String
    employmentType: String
    description: String
    salaryMin: Float
    salaryMax: Float
  }
  type JobApplication {
    id: Int!
    jobTitle: String!
    status: String!
    coverLetter: String
    applicantName: String!
    applicantEmail: String!
    createdAt: String!
  }
  type TransferResult { success: Boolean!, message: String!, balance: Float! }
  type RegisterResult { success: Boolean!, token: String, message: String! }
  type ChatResult { reply: String!, convoId: String! }

  type Query {
    me: User
    user(id: Int!): User
    account(accountNumber: String!): Account
    statement(accountNumber: String!): Statement
    blogPosts: [BlogPost!]!
    blogPost(id: Int!): BlogPost
    jobs: [Job!]!
    application(id: Int!): JobApplication
  }
  type Mutation {
    transfer(toAccountNumber: String!, amount: Float!, memo: String): TransferResult!
    register(name: String!, username: String!, email: String, password: String!): RegisterResult!
    addComment(postId: Int!, body: String!): BlogComment!
    apply(jobId: Int!, coverLetter: String): JobApplication!
    supportChat(message: String!, convoId: String): ChatResult!
  }
`;

function gqlAuth(ctx) {
  if (!ctx.user) throw new Error('Unauthorized: missing or invalid session token');
  return ctx.user;
}

function gqlUser(user) {
  if (!user) return null;
  const { password, api_key, ...rest } = user;
  return { ...rest, apiKey: api_key ?? null };
}

// Resolve the signed-in user inside the active trace context.
async function traceUser() {
  const { als } = await import('./trace.js');
  const store = als.getStore();
  if (!store?.actorId) return null;
  return safeUser(await getUserById(store.actorId));
}

const resolvers = {
  Query: {
    me: async (_p, _a, ctx) => {
      const user = gqlAuth(ctx);
      setOperation('me');
      return gqlUser(user);
    },
    // VULN: any user's details + secret API key by numeric id (BOLA)
    user: async (_p, { id }, ctx) => {
      gqlAuth(ctx);
      setOperation('user');
      setParams({ targetUserId: id });
      const target = await getUserById(id);
      if (!target) throw new Error(`User ${id} does not exist`);
      setResourceOwner({ userId: target.id });
      setMeta({ secret: 'api_key_accessed' });
      return gqlUser(target);
    },
    // VULN: any account's balance + transactions by account number (IDOR)
    account: async (_p, { accountNumber }, ctx) => {
      gqlAuth(ctx);
      setOperation('account');
      setParams({ accountNumber });
      const account = await getAccountByNumber(accountNumber);
      if (!account) throw new Error(`Account ${accountNumber} not found`);
      const txns = await getTransactions(account.id);
      setResourceOwner({ userId: account.user_id, accountNumber: account.account_number });
      setMeta({ balance: Number(account.balance), transactionCount: txns.length });
      return {
        accountNumber: account.account_number,
        type: account.type,
        balance: Number(account.balance),
        currency: account.currency,
        ownerUserId: account.user_id,
        transactions: txns.map((t) => ({
          id: t.id,
          description: t.description,
          amount: Number(t.amount),
          type: t.type,
          createdAt: new Date(t.created_at).toISOString(),
        })),
      };
    },
    // VULN: any account holder's statement (PII leak)
    statement: async (_p, { accountNumber }, ctx) => {
      gqlAuth(ctx);
      setOperation('statement');
      setParams({ accountNumber });
      const built = await buildStatement(accountNumber);
      if (!built) throw new Error(`Account ${accountNumber} not found`);
      setResourceOwner({ userId: built.statement.accountHolder.userId, accountNumber });
      setMeta({
        ownerName: built.statement.accountHolder.name,
        ownerAddress: built.statement.accountHolder.address,
        balance: built.statement.account.balance,
      });
      return {
        accountNumber: built.statement.account.accountNumber,
        ownerName: built.statement.accountHolder.name,
        ownerEmail: built.statement.accountHolder.email,
        address: built.statement.accountHolder.address,
        balance: built.statement.account.balance,
        currency: built.statement.account.currency,
        statementId: built.statement.statementId,
        textDocument: built.textDocument,
      };
    },
    blogPosts: async () => {
      setOperation('blogPosts');
      const posts = await listBlogPosts();
      return posts.map((p) => ({
        id: p.id, title: p.title, slug: p.slug, excerpt: p.excerpt, body: p.body,
        authorName: p.author_name, publishedAt: new Date(p.published_at).toISOString(),
        commentCount: p.comment_count ?? 0,
      }));
    },
    blogPost: async (_p, { id }) => {
      setOperation('blogPost');
      setParams({ postId: id });
      const post = await getBlogPost(id);
      if (!post) throw new Error(`Post ${id} not found`);
      const comments = await listComments(id);
      return {
        id: post.id, title: post.title, slug: post.slug, excerpt: post.excerpt, body: post.body,
        authorName: post.author_name, publishedAt: new Date(post.published_at).toISOString(),
        commentCount: comments.length,
      };
    },
    jobs: async () => {
      setOperation('jobs');
      const jobs = await listJobs();
      return jobs.map((j) => ({
        id: j.id, title: j.title, department: j.department, location: j.location,
        employmentType: j.employment_type, description: j.description,
        salaryMin: j.salary_min != null ? Number(j.salary_min) : null,
        salaryMax: j.salary_max != null ? Number(j.salary_max) : null,
      }));
    },
    // VULN: any applicant's cover letter + PII by application id
    application: async (_p, { id }, ctx) => {
      gqlAuth(ctx);
      setOperation('application');
      setParams({ applicationId: id });
      const app = await getApplication(id);
      if (!app) throw new Error(`Application ${id} not found`);
      setResourceOwner({ userId: app.user_id });
      setMeta({ secret: 'job_application_accessed' });
      return {
        id: app.id, jobTitle: app.job_title, status: app.status, coverLetter: app.cover_letter,
        applicantName: app.applicant_name, applicantEmail: app.applicant_email,
        createdAt: new Date(app.created_at).toISOString(),
      };
    },
  },
  Mutation: {
    // VULN: identical business-logic flaws over GraphQL
    transfer: async (_p, { toAccountNumber, amount, memo }, ctx) => {
      const user = gqlAuth(ctx);
      setOperation('transfer');
      const numAmount = Number(amount);
      setParams({ toAccountNumber, amount: numAmount });
      if (!toAccountNumber || !Number.isFinite(numAmount) || numAmount === 0) {
        throw new Error('Recipient account and a non-zero amount are required');
      }
      const source = await getAccountByUserId(user.id);
      if (!source) throw new Error('Source account not found');
      const target = await getAccountByNumber(toAccountNumber);
      const balanceBefore = Number(source.balance);
      const isNegativeExploit = numAmount < 0;
      const isOverdraftExploit = numAmount > 0 && numAmount > balanceBefore;

      const balanceAfter = await debit(source.id, numAmount);
      await createTransaction({
        accountId: source.id,
        fromUserId: user.id,
        toAccountNumber,
        amount: Math.abs(numAmount),
        type: 'TRANSFER',
        description: memo || (isNegativeExploit ? 'Reverse adjustment' : `Transfer to ${toAccountNumber}`),
        balanceAfter,
      });
      if (target) {
        await credit(target.id, numAmount);
        await createTransaction({
          accountId: target.id,
          fromUserId: user.id,
          toAccountNumber: target.account_number,
          amount: Math.abs(numAmount),
          type: isNegativeExploit ? 'TRANSFER' : 'DEPOSIT',
          description: isNegativeExploit
            ? `Reversed claim from ${user.name} (${source.account_number})`
            : `Received from ${user.name} (${source.account_number}): ${memo || 'Transfer'}`,
        });
      }
      setResourceOwner(target ? { userId: target.user_id, accountNumber: target.account_number } : null);
      setMeta({
        amount: numAmount, balanceBefore, balanceAfter, toAccountNumber,
        targetOwnerUserId: target?.user_id ?? null, sourceAccountNumber: source.account_number,
      });
      return {
        success: true,
        message: isNegativeExploit
          ? `Transfer processed. Balance credited by ZWL ${Math.abs(numAmount).toFixed(2)}.`
          : isOverdraftExploit
          ? `Overdraft transfer approved: ZWL ${numAmount.toFixed(2)} sent.`
          : `Transferred ZWL ${numAmount.toFixed(2)} to ${toAccountNumber}.`,
        balance: balanceAfter,
      };
    },
    register: async (_p, { name, username, email, password }) => {
      setOperation('register');
      setParams({ name, username, email });
      if (!name || !username || !password || String(password).length < 4) {
        throw new Error('Name, username and a password of at least 4 characters are required');
      }
      if (await getUserByUsername(username)) throw new Error('That username is already taken');
      const { user, account } = await createUser({ name, username, email, password });
      const token = await createSession(user.id);
      setResourceOwner({ userId: user.id, accountNumber: account.account_number });
      setMeta({ openedWith: '500 ZWL opening deposit' });
      return {
        success: true,
        token,
        message: `Account ${account.account_number} opened with a 500 ZWL deposit for ${user.name}.`,
      };
    },
    addComment: async (_p, { postId, body }, ctx) => {
      const user = ctx.user;
      setOperation('addComment');
      setParams({ postId });
      if (!body || !String(body).trim()) throw new Error('Comment body is required');
      const comment = await addComment({
        postId, userId: user?.id ?? null, authorName: user?.name ?? 'Guest', body: String(body),
      });
      setResourceOwner(user ? { userId: user.id } : null);
      return {
        id: comment.id, authorName: comment.author_name, body: comment.body,
        createdAt: new Date(comment.created_at).toISOString(),
      };
    },
    apply: async (_p, { jobId, coverLetter }, ctx) => {
      const user = gqlAuth(ctx);
      setOperation('apply');
      setParams({ jobId });
      const app = await createApplication({ jobId, userId: user.id, coverLetter });
      const full = await getApplication(app.id);
      return {
        id: full.id, jobTitle: full.job_title, status: full.status, coverLetter: full.cover_letter,
        applicantName: full.applicant_name, applicantEmail: full.applicant_email,
        createdAt: new Date(full.created_at).toISOString(),
      };
    },
    supportChat: async (_p, { message, convoId }) => {
      setOperation('supportChat');
      setParams({ message });
      const cid = convoId || `convo_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      const user = await traceUser();
      const account = user ? await getAccountByUserId(user.id) : null;
      await saveChat({ convoId: cid, userId: user?.id ?? null, role: 'user', text: message });
      const reply = await chatbotRespond(message, {
        user,
        account,
        lookupAccount: (num) => getAccountByNumber(num), // VULN: reads any account
      });
      await saveChat({ convoId: cid, userId: user?.id ?? null, role: 'bot', text: reply });
      return { reply, convoId: cid };
    },
  },
};

export const yoga = createYoga({
  schema: createSchema({ typeDefs, resolvers }),
  graphqlEndpoint: '/graphql',
  context: ({ req }) => ({ user: req.user ?? null, token: req.token ?? null }),
  maskedErrors: false,
  landingPage: true,
});
