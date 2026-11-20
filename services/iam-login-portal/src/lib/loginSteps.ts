/** The screens of the sign-in wizard (see app/login/LoginForm.tsx). */
export type LoginStep = "username" | "password" | "enroll" | "code" | "submitting-no-code";

/**
 * What pressing Enter does on each screen.
 *
 * Pressing Enter in a text box submits the <form>. On the username and password screens the "Next" button is a plain
 * `type="button"` (it advances the wizard and, on the password screen, asks iam-auth-svc what comes next), so without this
 * the browser would submit the REAL sign-in right there, half filled in, and show an error instead of moving on. Enter must
 * do exactly what clicking Next does on those two screens. On the other screens the form's own submit button is what
 * should run, so Enter is left alone.
 */
export type EnterAction = "advance-username" | "advance-password" | "submit";

export function enterAction(step: LoginStep): EnterAction {
  switch (step) {
    case "username":
      return "advance-username";
    case "password":
      return "advance-password";
    default:
      return "submit";
  }
}
