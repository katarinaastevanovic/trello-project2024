import { Component, OnInit } from '@angular/core';
import { NotificationService } from '../../services/notifications/notifications.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-notifications-user',
  standalone: true,
  imports: [CommonModule], 
  templateUrl: './notifications-user.component.html',
  styleUrls: ['./notifications-user.component.css']
})
export class NotificationsUserComponent implements OnInit {
  notifications: any[] = [];
  errorMessage: string = '';

  constructor(private notificationService: NotificationService) {}

  ngOnInit(): void {
    const username = localStorage.getItem('username');
    if (!username) {
      this.errorMessage = 'User not logged in.';
      return;
    }

    this.notificationService.getNotifications(username).subscribe({
      next: (data) => {
        this.notifications = data;
      },
      error: (err) => {
        this.errorMessage = 'Failed to load notifications.';
        console.error(err);
      }
    });
  }

  markAsRead(notificationId: string): void {
    const username = localStorage.getItem('username');
    if (!username) return;

    this.notificationService.markAsRead(notificationId, username).subscribe({
      next: () => {
        const notification = this.notifications.find((n) => n.id === notificationId);
        if (notification) {
          notification.is_read = true;
        }
      },
      error: (err) => {
        console.error('Failed to mark notification as read:', err);
      }
    });
  }
}
