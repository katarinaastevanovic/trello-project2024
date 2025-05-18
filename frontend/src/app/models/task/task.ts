export class Task {
    constructor(
      public id: number,
      public projectId: string,
      public title: string,
      public description: string,
      public completed: boolean,
      public dependsOn?: string
      
    ) {}
  }
  
