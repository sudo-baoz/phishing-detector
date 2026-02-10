/**
 * 403 – Access Denied / Security Block. Red theme.
 */
import { ShieldAlert } from 'lucide-react';
import ErrorCard from '../../components/ErrorCard';

export default function ForbiddenPage() {
  return (
    <div className="min-h-[60vh] flex items-center justify-center px-4 py-12">
      <ErrorCard
        code="403"
        title="Access Denied"
        description="You do not have clearance to access this classified sector."
        icon={ShieldAlert}
        accentClass="text-red-400"
      />
    </div>
  );
}
