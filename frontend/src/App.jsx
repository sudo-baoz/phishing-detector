import Scanner from './components/Scanner';
import LanguageSwitcher from './components/LanguageSwitcher';

function App() {
  return (
    <div className="min-h-screen bg-black">
      <LanguageSwitcher />
      <Scanner />
    </div>
  );
}

export default App;
