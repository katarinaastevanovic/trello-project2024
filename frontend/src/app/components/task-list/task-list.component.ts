import { Component, OnInit } from '@angular/core';
import { TaskService } from '../../services/task/task.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-task-list',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './task-list.component.html',
  styleUrl: './task-list.component.css'
})

export class TaskListComponent implements OnInit {
  tasks: any[] = []; 

  constructor(private taskService: TaskService) {}

  ngOnInit(): void {
    this.getAllTasks();
  }

  getAllTasks(): void {
    this.taskService.getAllTasks().subscribe(
      (data) => (this.tasks = data),
      (error) => console.error('Error fetching tasks:', error)
    );
  }
}