import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RemoveMembersComponent } from './remove-members.component';

describe('RemoveMembersComponent', () => {
  let component: RemoveMembersComponent;
  let fixture: ComponentFixture<RemoveMembersComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RemoveMembersComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RemoveMembersComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
