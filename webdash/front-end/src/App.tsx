import React from 'react';
import { useState } from 'react';
import { format } from 'date-fns';
import { 
  Shield, 
  Activity, 
  Users, 
  TrendingUp, 
  RefreshCw,
  Clock
} from 'lucide-react';

import { useAttackData } from './hooks/useAttackData';
import { StatsCard } from './components/StatsCard';
import { ChartCard } from './components/ChartCard';
import { DatePicker } from './components/DatePicker';
import { AttackTimelineChart } from './components/AttackTimelineChart';
import { AttackTypeChart } from './components/AttackTypeChart';
import { ProtocolDistribution } from './components/ProtocolDistribution';
import { AttackTable } from './components/AttackTable';
import { LoadingSpinner } from './components/LoadingSpinner';
import { ErrorMessage } from './components/ErrorMessage';

function App() {
  // Get today's date in DD-MM-YYYY format
  const getTodayFormatted = (): string => {
    const today = new Date();
    const day = today.getDate().toString().padStart(2, '0');
    const month = (today.getMonth() + 1).toString().padStart(2, '0');
    const year = today.getFullYear().toString();
    return `${day}-${month}-${year}`;
  };

  const [selectedDate, setSelectedDate] = useState<string>(getTodayFormatted());
  const { data, loading, error, lastUpdated, stats, refetch } = useAttackData(selectedDate);

  const handleDateChange = (date: string) => {
    setSelectedDate(date);
  };

  if (loading && data.length === 0) {
    return <LoadingSpinner />;
  }

  // if (error) {
    // return <ErrorMessage message={error} onRetry={refetch} />;

  // }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-lg border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
                <p className="text-gray-500">Real-time attack monitoring and analysis</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <DatePicker
                selectedDate={selectedDate}
                onDateChange={handleDateChange}
                loading={loading}
              />
              <button
                onClick={refetch}
                disabled={loading}
                className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors duration-200 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatsCard
            title="Total Attacks"
            value={stats.totalAttacks.toLocaleString()}
            icon={Shield}
            color="red"
            subtitle="Detected incidents"
          />
          <StatsCard
            title="Unique Source IPs"
            value={stats.uniqueIPs}
            icon={Users}
            color="blue"
            subtitle="Different attackers"
          />
          <StatsCard
            title="Average Probability"
            value={`${(stats.avgProbability * 100).toFixed(1)}%`}
            icon={TrendingUp}
            color="yellow"
            subtitle="Threat confidence"
          />
          <StatsCard
            title="Most Common Attack"
            value={stats.mostCommonAttack}
            icon={Activity}
            color="green"
            subtitle="Primary threat type"
          />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          <ChartCard title="Attack Timeline">
            <AttackTimelineChart data={data} />
          </ChartCard>
          
          <ChartCard title="Attack Types Distribution">
            <AttackTypeChart data={data} />
          </ChartCard>
          
          <ChartCard title="Protocol Distribution" className="lg:col-span-2">
            <div className="max-w-md mx-auto">
              <ProtocolDistribution data={data} />
            </div>
          </ChartCard>
        </div>

        {/* Attack Details Table */}
        <AttackTable data={data} />
      </main>
    </div>
  );
}

export default App;