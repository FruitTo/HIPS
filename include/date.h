#ifndef DATE_H
#define DATE_H
#include <string>
std::string currentDate()
{
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    int year = timeinfo->tm_year + 1900;
    int month = timeinfo->tm_mon + 1;
    int day = timeinfo->tm_mday;
    int dateday = timeinfo->tm_wday;

    std::string dayName;

    switch (dateday)
    {
    case 0:
        dayName = "Sunday";
        break;
    case 1:
        dayName = "Monday";
        break;
    case 2:
        dayName = "Tuesday";
        break;
    case 3:
        dayName = "Wednesday";
        break;
    case 4:
        dayName = "Thursday";
        break;
    case 5:
        dayName = "Friday";
        break;
    case 6:
        dayName = "Saturday";
        break;
    default:
        dayName = "Unknown";
        break;
    }

    std::stringstream ss_day, ss_month;
    ss_day << std::setfill('0') << std::setw(2) << day;
    ss_month << std::setfill('0') << std::setw(2) << month;

    std::string date = dayName + "-" + ss_day.str() + "-" + ss_month.str() + "-" + std::to_string(year);
    return date;
}

std::string getPath(){
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    int year = timeinfo->tm_year + 1900;
    int month = timeinfo->tm_mon + 1;
    int day = timeinfo->tm_mday;

    std::stringstream ss_day, ss_month;
    ss_day << std::setfill('0') << std::setw(2) << day;
    ss_month << std::setfill('0') << std::setw(2) << month;

    return "./logs/" + std::to_string(year) + "/" + ss_month.str() + "/" + ss_day.str() + "/";
}

#endif