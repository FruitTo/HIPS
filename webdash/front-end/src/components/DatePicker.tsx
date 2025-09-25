import React from 'react';
import { Calendar } from 'lucide-react';

interface DatePickerProps {
  selectedDate: string;
  onDateChange: (date: string) => void;
  loading?: boolean;
}

export const DatePicker: React.FC<DatePickerProps> = ({
  selectedDate,
  onDateChange,
  loading = false
}) => {
  // Convert from DD-MM-YYYY to YYYY-MM-DD for input
  const formatDateForInput = (dateStr: string): string => {
    const [day, month, year] = dateStr.split('-');
    return `${year}-${month}-${day}`;
  };

  // Convert from YYYY-MM-DD to DD-MM-YYYY for API
  const formatDateForAPI = (dateStr: string): string => {
    const [year, month, day] = dateStr.split('-');
    return `${day}-${month}-${year}`;
  };

  const handleDateChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const inputDate = e.target.value;
    if (inputDate) {
      const apiDate = formatDateForAPI(inputDate);
      onDateChange(apiDate);
    }
  };

  // Get today's date in DD-MM-YYYY format
  const getTodayFormatted = (): string => {
    const today = new Date();
    const day = today.getDate().toString().padStart(2, '0');
    const month = (today.getMonth() + 1).toString().padStart(2, '0');
    const year = today.getFullYear().toString();
    return `${day}-${month}-${year}`;
  };

  const inputValue = selectedDate ? formatDateForInput(selectedDate) : formatDateForInput(getTodayFormatted());

  return (
    <div className="flex items-center space-x-2">
      <div className="relative">
        <Calendar className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
        <input
          type="date"
          value={inputValue}
          onChange={handleDateChange}
          disabled={loading}
          className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white disabled:opacity-50 disabled:cursor-not-allowed"
        />
      </div>
      <div className="text-sm text-gray-500">
        Selected: {selectedDate || getTodayFormatted()}
      </div>
    </div>
  );
};