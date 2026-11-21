import { page } from "./cli-pages.ts";

const NO_ACCOUNT_CREATED = `        <p class="outcome">No account was created.</p>`;

export function renderSignupClosedPage(): string {
  return page(
    "maruhi — sign-ups closed",
    `        <h1>Sign-ups are closed</h1>
        <p>This maruhi server is not accepting new accounts right now.</p>
${NO_ACCOUNT_CREATED}
        <h2>What you can do</h2>
        <ul>
          <li>
            If you already have an account under a different GitHub identity, sign in with that
            one.
          </li>
          <li>Otherwise, contact the operator of this server about getting access.</li>
        </ul>`,
  );
}

export function renderSignupInviteRequiredPage(): string {
  return page(
    "maruhi — invite required",
    `        <h1>Sign-ups are invite-only</h1>
        <p>This maruhi server requires a sign-up invite code to create an account.</p>
${NO_ACCOUNT_CREATED}
        <h2>What you can do</h2>
        <ul>
          <li>
            If you received an invite, open the sign-up link that came with it &mdash; the link
            carries your code.
          </li>
          <li>To request an invite, contact the operator of this server.</li>
          <li>
            If you already have an account under a different GitHub identity, sign in with that
            one.
          </li>
        </ul>`,
  );
}

export function renderSignupInviteInvalidPage(): string {
  return page(
    "maruhi — invite code can't be used",
    `        <h1>This sign-up invite code can&#39;t be used</h1>
        <p>The code is invalid, has expired, or was already used.</p>
${NO_ACCOUNT_CREATED}
        <h2>What you can do</h2>
        <ul>
          <li>Ask the operator of this server for a new sign-up invite code.</li>
          <li>
            If sign-ups are open on this server, you can also
            <a href="/auth/github/start">sign up without a code</a>.
          </li>
        </ul>`,
  );
}
