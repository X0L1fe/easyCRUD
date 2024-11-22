// Функция для отображения/скрытия формы редактирования
function toggleEditForm(itemId) {
    const form = document.getElementById(`form-${itemId}`);
    const itemData = document.querySelector(`#item-${itemId} .item-data`);
    const updateBtn = document.getElementById(`update-btn-${itemId}`);
    const deleteBtn = document.getElementById(`delete-btn-${itemId}`);
    const isFormVisible = form.style.display === 'block';

    if (isFormVisible) {
        // Скрыть форму, показать данные и кнопки
        form.style.display = 'none';
        itemData.style.display = 'inline';
        updateBtn.style.display = 'inline';
        deleteBtn.style.display = 'inline';
    } else {
        // Показать форму, скрыть данные и кнопки
        form.style.display = 'block';
        itemData.style.display = 'none';
        updateBtn.style.display = 'none';
        deleteBtn.style.display = 'none';
    }
}