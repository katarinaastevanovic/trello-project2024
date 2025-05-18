import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AddTasksComponent } from './components/add-tasks/add-tasks.component';
import { AddProjectsComponent } from './components/add-projects/add-projects.component';
import { RemoveMembersComponent } from './components/remove-members/remove-members.component';
import { AddMembersComponent } from './components/add-members/add-members.component';
import { ProjectListComponent } from './components/project-list/project-list.component';
import { ProjectDetailsComponent } from './components/project-details/project-details.component';
import { TaskListComponent } from './components/task-list/task-list.component';
import { RegisterComponent } from './components/register/register.component';
import { DeleteAccountComponent } from './components/delete-account/delete-account.component';
import { LoginComponent } from './components/login/login.component';
import { VerifyCodeComponent } from './components/verify-code/verify-code.component';
import { AddMembersToTaskComponent } from './components/add-members-to-task/add-members-to-task.component';
import { ViewMembersTaskComponent } from './components/view-members-task/view-members-task.component';

import { UsersProjectsComponent } from './components/users-projects/users-projects.component';
import { UsersProfileComponent } from './components/users-profile/users-profile.component';
import { ChangePasswordComponent } from './components/change-password/change-password.component';
import { AuthGuard } from './guards/auth.guard';
import { RoleGuard } from './guards/role.guard';

import { NotificationsUserComponent } from './components/notifications-user/notifications-user.component';
import { ResetPasswordComponent } from './reset-password/reset-password.component';



// export const routes: Routes = [
//   { path: 'add-tasks', component: AddTasksComponent },
//   { path: 'remove-members', component: RemoveMembersComponent },
//   { path: 'add-projects', component: AddProjectsComponent }, 
//   { path: '', redirectTo: '/add-projects', pathMatch: 'full' }, 
//   { path: 'add-members', component: AddMembersComponent },
//   { path: 'add-projects', component: AddProjectsComponent },
//   { path: 'add-members', component: AddMembersComponent },
//   { path: 'projects-list', component: ProjectListComponent },
//   { path: 'project/:id', component: ProjectDetailsComponent }, 
//   { path: '', redirectTo: '/projects-list', pathMatch: 'full' },
//   { path: 'add-projects', component: AddProjectsComponent }, 
//   { path: '', redirectTo: '/add-projects', pathMatch: 'full' }, 
//   { path: 'add-members', component: AddMembersComponent },
//   { path: 'task-list', component: TaskListComponent },

// ];

// export const routes: Routes = [
//   { path: 'add-tasks', component: AddTasksComponent },
//   { path: 'remove-members', component: RemoveMembersComponent },
//   { path: 'remove-members/:id', component: RemoveMembersComponent },
//   { path: 'add-projects', component: AddProjectsComponent }, 
//   { path: '', redirectTo: '/add-projects', pathMatch: 'full' },
//   { path: 'project/:id/add-members', component: AddMembersComponent },
//   { path: 'projects-list', component: ProjectListComponent },
//   { path: 'project/:id', component: ProjectDetailsComponent }, 
//   { path: '', redirectTo: '/projects-list', pathMatch: 'full' },
//   { path: 'task-list', component: TaskListComponent },
//   { path: '', redirectTo: '/projects-list', pathMatch: 'full' }, 
//   { path: 'register', component: RegisterComponent },
//   { path: 'users-projects', component: UsersProjectsComponent },
//   { path: 'delete-account', component: DeleteAccountComponent },
//   { path: 'login', component: LoginComponent }, 
//   { path: '', redirectTo: '/login', pathMatch: 'full' },
//   { path: 'verify', component: VerifyCodeComponent },
//   { path: 'project/:projectId/task/:taskId/add-members', component: AddMembersToTaskComponent },
//   { path: 'project/:projectId/task/:taskId/members', component: ViewMembersTaskComponent },
//   { path: 'magic-login', component: LoginComponent },
//   { path: 'users-profile', component: UsersProfileComponent }
// ];

export const routes: Routes = [
 // Stranice dostupne bez autentifikacije
 { path: '', redirectTo: '/login', pathMatch: 'full' },
 { path: 'login', component: LoginComponent },
 { path: 'register', component: RegisterComponent },
 { path: 'verify', component: VerifyCodeComponent },
 { path: 'magic-login', component: LoginComponent },
 { path: 'reset-password', component: ResetPasswordComponent },


 // Stranice zaštićene autentifikacijom
 { path: 'projects-list', component: ProjectListComponent, canActivate: [AuthGuard] },
 { path: 'project/:id', component: ProjectDetailsComponent, canActivate: [AuthGuard] },
 { path: 'project/:id/add-members', component: AddMembersComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 { path: 'project/:projectId/task/:taskId/add-members', component: AddMembersToTaskComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 { path: 'project/:projectId/task/:taskId/members', component: ViewMembersTaskComponent, canActivate: [AuthGuard] },
 { path: 'task-list', component: TaskListComponent, canActivate: [AuthGuard] },
 { path: 'users-profile', component: UsersProfileComponent, canActivate: [AuthGuard] },
 { path: 'users-projects', component: UsersProjectsComponent, canActivate: [AuthGuard] },
 { path: 'delete-account', component: DeleteAccountComponent, canActivate: [RoleGuard], data: { roles: ['manager', 'member'] } },
 { path: 'add-tasks', component: AddTasksComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 { path: 'add-projects', component: AddProjectsComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 { path: 'remove-members', component: RemoveMembersComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 { path: 'remove-members/:id', component: RemoveMembersComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 { path: 'change-password', component: ChangePasswordComponent, canActivate: [RoleGuard], data: { roles: ['manager', 'member'] } },
 { path: 'notifications-user', component: NotificationsUserComponent },
 { path: 'delete-project/:id', component: ProjectDetailsComponent, canActivate: [RoleGuard], data: { roles: ['manager'] } },
 // Fallback ruta za neprijavljene korisnike
 { path: '**', redirectTo: '/login' },

  // // Rute za korisnike
  // { path: 'register', component: RegisterComponent },
  // { path: 'login', component: LoginComponent },
  // { path: 'magic-login', component: LoginComponent },
  // { path: 'users-profile', component: UsersProfileComponent },
  // { path: 'users-projects', component: UsersProjectsComponent },
  // { path: 'delete-account', component: DeleteAccountComponent },
  // { path: 'notifications-user', component: NotificationsUserComponent },

  // // Rute za dodavanje i uklanjanje članova
  // { path: 'add-tasks', component: AddTasksComponent },
  // { path: 'add-projects', component: AddProjectsComponent },
  // { path: 'remove-members', component: RemoveMembersComponent },
  // { path: 'remove-members/:id', component: RemoveMembersComponent },

  // // Ostale rute
  // { path: 'verify', component: VerifyCodeComponent },
  // { path: 'magic-login', component: LoginComponent },
  // { path: 'users-profile', component: UsersProfileComponent },
  // { path: 'change-password',component:ChangePasswordComponent },
  // { path: '**', redirectTo: '/projects-list' },

];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}





