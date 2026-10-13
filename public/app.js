// Standup controls: step through the briefing's sections one at a time.
// The page works without this script; <details> sections open and close natively.
(() => {
  const sections = [...document.querySelectorAll("details.section")];
  const toolbar = document.querySelector(".toolbar");
  if (!sections.length || !toolbar) return;

  const position = toolbar.querySelector(".toolbar-position");
  const titleOf = (s) => s.querySelector(".section-title")?.textContent ?? "";
  let current = -1;

  function update() {
    const open = sections.filter((s) => s.open);
    if (open.length === 1) {
      current = sections.indexOf(open[0]);
      position.textContent = `${current + 1} / ${sections.length} · ${titleOf(open[0])}`;
    } else {
      position.textContent = open.length === 0 ? "" : `${open.length} open`;
    }
  }

  function show(i, behavior = "smooth") {
    if (i < 0 || i >= sections.length) return;
    sections.forEach((s, j) => (s.open = j === i));
    current = i;
    sections[i].scrollIntoView({ behavior, block: "start" });
    sections[i].querySelector("summary")?.focus({ preventScroll: true });
    update();
  }

  const actions = {
    next: () => show(Math.min(current + 1, sections.length - 1)),
    prev: () => show(Math.max(current - 1, 0)),
    expand: () => { sections.forEach((s) => (s.open = true)); update(); },
    collapse: () => { sections.forEach((s) => (s.open = false)); current = -1; update(); },
  };

  toolbar.addEventListener("click", (e) => {
    const action = e.target.closest("button[data-action]")?.dataset.action;
    if (action) actions[action]();
  });

  sections.forEach((s) => s.addEventListener("toggle", update));

  const keys = { n: "next", ArrowRight: "next", p: "prev", ArrowLeft: "prev", e: "expand", c: "collapse" };
  document.addEventListener("keydown", (e) => {
    if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (e.target.closest("input, textarea, select, [contenteditable]")) return;
    const action = keys[e.key];
    if (!action) return;
    e.preventDefault();
    actions[action]();
  });

  // A link like /#ransomware opens that section.
  const fromHash = sections.findIndex((s) => `#${s.id}` === location.hash);
  if (fromHash !== -1) show(fromHash, "instant");
  window.addEventListener("hashchange", () => {
    const i = sections.findIndex((s) => `#${s.id}` === location.hash);
    if (i !== -1) show(i);
  });

  update();
})();
