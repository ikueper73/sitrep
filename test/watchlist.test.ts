import { describe, expect, it } from "vitest";
import { matchVendorProduct, normalize, productMatches, vendorMatches, type WatchEntry } from "../src/watchlist/match";

const entry = (vendors: string[], products: string[]): WatchEntry => ({ label: "x", vendors, products, tier: 1 });

describe("normalize", () => {
  it("lowercases, strips accents and punctuation", () => {
    expect(normalize("Dassault Systèmes, Inc.")).toBe("dassault systemes inc");
    expect(normalize("Notepad++")).toBe("notepadpp");
  });
});

describe("vendorMatches", () => {
  it("matches aliases and longer KEV vendor names", () => {
    expect(vendorMatches(entry(["VMware", "Broadcom"], []), "Broadcom")).toBe(true);
    expect(vendorMatches(entry(["Hitachi"], []), "Hitachi Vantara")).toBe(true);
    expect(vendorMatches(entry(["Cisco"], []), "Microsoft")).toBe(false);
  });

  it("does not match partial words", () => {
    expect(vendorMatches(entry(["SAP"], []), "Sapphire")).toBe(false);
  });
});

describe("productMatches", () => {
  it("matches whole-word phrases only", () => {
    const e = entry(["Microsoft"], ["sharepoint"]);
    expect(productMatches(e, "SharePoint Server")).toBe(true);
    expect(productMatches(entry(["Cisco"], ["ios"]), "IOS XE Software")).toBe(true);
    expect(productMatches(entry(["Cisco"], ["ios"]), "Adaptive Security Appliance")).toBe(false);
    expect(productMatches(entry(["Microsoft"], ["edge"]), "Exchange Server")).toBe(false);
  });

  it("treats an empty product list as vendor-wide", () => {
    expect(productMatches(entry(["Acme"], []), "Anything")).toBe(true);
  });
});

describe("matchVendorProduct", () => {
  it("requires vendor and product to match", () => {
    const entries = [entry(["Microsoft"], ["sharepoint"]), entry(["Citrix"], ["netscaler", "adc"])];
    expect(matchVendorProduct(entries, "Microsoft", "SharePoint")).toHaveLength(1);
    expect(matchVendorProduct(entries, "Microsoft", "Windows")).toHaveLength(0);
    expect(matchVendorProduct(entries, "Citrix", "NetScaler ADC and NetScaler Gateway")).toHaveLength(1);
  });
});
