import { describe, expect, it } from "vitest";

import { arrivalFor } from "./arrival";

describe("arriving on the landing page", () => {
  it("asks which deployment when this browser holds no session", () => {
    expect(arrivalFor(null, false)).toEqual({ kind: "form" });
    expect(arrivalFor(null, true)).toEqual({ kind: "form" });
  });

  it("opens the application when the session and the keys are both there", () => {
    expect(arrivalFor("@michel:twalk.localhost", true)).toEqual({
      kind: "signed-in",
      owner: "@michel:twalk.localhost",
      keysGone: false,
    });
  });

  /**
   * The one this module exists for. Before #433 this case left the landing
   * page entirely for `/recover`, and an owner without their key had no way
   * on — to screens that needed no key at all.
   */
  it("still opens the application when the browser threw the keys away", () => {
    const arrival = arrivalFor("@michel:twalk.localhost", false);

    expect(arrival).toEqual({
      kind: "signed-in",
      owner: "@michel:twalk.localhost",
      keysGone: true,
    });
    expect(arrival.kind).not.toBe("form");
  });
});
