$(document).ready(function() {
    // Variables to store original and updated profile info
    let profileData = {
        name: "John Doe",
        email: "johndoe@gmail.com",
        phone: "+123456789",
        location: "New York, USA"
    };

    // Function to display profile info in non-editable format
    function displayProfile() {
        $('.profile-info').html(`
            <h3>${profileData.name}</h3>
            <p>Email: ${profileData.email}</p>
            <p>Phone: ${profileData.phone}</p>
            <p>Location: ${profileData.location}</p>
            <a href="#" id="editProfile" class="btn btn-primary mt-2">Edit Profile</a>
        `);
    }

    // Function to display profile info in editable format
    function editProfile() {
        $('.profile-info').html(`
            <h3><input type="text" id="name" class="form-control" value="${profileData.name}"></h3>
            <p>Email: <input type="email" id="email" class="form-control" value="${profileData.email}"></p>
            <p>Phone: <input type="text" id="phone" class="form-control" value="${profileData.phone}"></p>
            <p>Location: <input type="text" id="location" class="form-control" value="${profileData.location}"></p>
            <button id="saveProfile" class="btn btn-success mt-2">Save</button>
            <button id="cancelEdit" class="btn btn-secondary mt-2">Cancel</button>
        `);
    }

    // Initially display the profile info
    displayProfile();

    // Event handler for Edit Profile button
    $(document).on('click', '#editProfile', function(e) {
        e.preventDefault();
        editProfile();
    });

    // Event handler for Save button
    $(document).on('click', '#saveProfile', function() {
        // Get new values from input fields
        profileData.name = $('#name').val();
        profileData.email = $('#email').val();
        profileData.phone = $('#phone').val();
        profileData.location = $('#location').val();

        // Update profile display with new values
        displayProfile();
    });

    // Event handler for Cancel button
    $(document).on('click', '#cancelEdit', function() {
        // Revert to display mode without saving any changes
        displayProfile();
    });
});
