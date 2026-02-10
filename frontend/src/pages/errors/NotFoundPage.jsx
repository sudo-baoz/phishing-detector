/**
 * 404 – Lost Signal / Target Unreachable. Blue/Cyan theme.
 */
import { SearchX } from 'lucide-react';
import ErrorCard from '../../components/ErrorCard';

export default function NotFoundPage() {
  return (
    <div className="min-h-[60vh] flex items-center justify-center px-4 py-12">
      <ErrorCard
        code="404"
        title="Target Not Found"
        description="The URL you are looking for has vanished into the digital void."
        icon={SearchX}
        accentClass="text-cyan-400"
      />
    </div>
  );
}
