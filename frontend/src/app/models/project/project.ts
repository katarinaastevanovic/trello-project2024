// src/app/models/project.ts
export interface Project {
  id: string;
  name: string;
  members: { id: string; username: string; name: string }[];
  expectedEndDate: Date | string;
  minMembers?: number;
  maxMembers?: number;
  managerId?: string;
}

