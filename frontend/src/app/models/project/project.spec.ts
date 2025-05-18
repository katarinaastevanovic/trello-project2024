import { Project } from './project';

describe('Project', () => {
  it('should create an instance', () => {
    expect(new Project('projectId123', 'Project Alpha', '2024-12-31T00:00:00Z', 3, 10, 'managerId123')).toBeTruthy();
  });
});
