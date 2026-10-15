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

  // A link like /#ransomware opens that section; a link to an item inside a
  // section (e.g. from "Today's focus") opens its section and scrolls to it.
  function openHash(behavior) {
    const id = decodeURIComponent(location.hash.slice(1));
    if (!id) return;
    const i = sections.findIndex((s) => s.id === id);
    if (i !== -1) return show(i, behavior);
    const target = document.getElementById(id);
    const section = target?.closest("details.section");
    if (!target || !section) return;
    sections.forEach((s) => (s.open = s === section));
    target.closest("details:not(.section)")?.setAttribute("open", ""); // e.g. the ICS group
    current = sections.indexOf(section);
    update();
    target.scrollIntoView({ behavior, block: "center" });
    target.classList.remove("flash");
    void target.offsetWidth; // restart the highlight animation
    target.classList.add("flash");
  }
  openHash("instant");
  window.addEventListener("hashchange", () => openHash("smooth"));

  update();
})();
