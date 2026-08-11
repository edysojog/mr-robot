// Reusable terminal-style typing effect. Reveals every .type-target element
// inside a container char-by-char, in document order, with a blinking
// cursor at the writing edge (see .type-target.typing in terminal.css).
// A single shared generation counter means starting a new play() (e.g.
// navigating to another screen mid-type) cleanly cancels whatever was
// still typing rather than fighting it for the same DOM.
const Typewriter = (() => {
  let generation = 0;

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function typeOne(el, text, gen, speed) {
    el.textContent = '';
    el.classList.add('typing');
    for (let i = 0; i <= text.length; i++) {
      if (gen !== generation) return;
      el.textContent = text.slice(0, i);
      await sleep(speed);
    }
    el.classList.remove('typing');
  }

  // container: a DOM element or a selector string. Types every .type-target
  // found inside it, one after another.
  async function play(container, speed = 12) {
    generation++;
    const gen = generation;
    const root = typeof container === 'string' ? document.querySelector(container) : container;
    if (!root) return;

    const targets = root.querySelectorAll('.type-target');
    targets.forEach((el) => {
      if (el.dataset.full === undefined) el.dataset.full = el.textContent;
      el.textContent = ''; // blank every line up front so later ones don't flash before their turn
    });

    for (const el of targets) {
      if (gen !== generation) return;
      await typeOne(el, el.dataset.full, gen, speed);
      await sleep(70);
    }
  }

  return { play };
})();
