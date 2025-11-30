// navbar.js
document.addEventListener('DOMContentLoaded', () => {
  const loginBtn = document.getElementById('loginBtn');
  const loginModal = document.getElementById('loginModal');
  const closeLogin = document.getElementById('closeLogin');
  const facebookLogin = document.getElementById('facebookLogin');
  const emailLoginBtn = document.getElementById('emailLoginBtn');
  const signupBtn = document.getElementById('signupBtn');

  loginBtn.addEventListener('click', () => loginModal.classList.remove('hidden'));
  closeLogin.addEventListener('click', () => loginModal.classList.add('hidden'));
  loginModal.addEventListener('click', (e) => { if (e.target === loginModal) loginModal.classList.add('hidden'); });

  // Facebook login placeholder
  facebookLogin.addEventListener('click', () => {
    // Replace this with real OAuth redirect to your backend (e.g. /auth/facebook)
    alert('Facebook login - redirect to Facebook OAuth (implement on backend).');
  });

  emailLoginBtn.addEventListener('click', () => {
    const email = document.getElementById('loginEmail').value;
    const pass = document.getElementById('loginPassword').value;
    if (!email || !pass) return alert('Enter email and password.');
    // Replace with actual auth call to your backend
    alert('Email login (demo) — implement real authentication server-side.');
  });

  signupBtn.addEventListener('click', () => {
    alert('Sign up flow — implement server-side signup or use OAuth.');
  });
});
