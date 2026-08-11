// Minimal screen-swap state helper. No framework needed for a 2-4 screen app.
const AppState = {
  show(screenId) {
    document.querySelectorAll('.screen').forEach((el) => el.classList.remove('active'));
    document.getElementById(screenId).classList.add('active');
  },
};
