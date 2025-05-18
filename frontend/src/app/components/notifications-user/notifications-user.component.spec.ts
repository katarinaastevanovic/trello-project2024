import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NotificationsUserComponent } from './notifications-user.component';

describe('NotificationsUserComponent', () => {
  let component: NotificationsUserComponent;
  let fixture: ComponentFixture<NotificationsUserComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NotificationsUserComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(NotificationsUserComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
